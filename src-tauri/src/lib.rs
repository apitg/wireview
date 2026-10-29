#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProtocolStat {
    name: String,
    packets: usize,
    bytes: usize,
    share: f64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Endpoint {
    address: String,
    packets: usize,
    bytes: usize,
    role: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Conversation {
    source: String,
    destination: String,
    protocol: String,
    packets: usize,
    bytes: usize,
}
#[derive(Serialize)]
struct Observation {
    kind: String,
    title: String,
    detail: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PacketSummary {
    number: usize,
    timestamp: i64,
    source: String,
    destination: String,
    protocol: String,
    bytes: usize,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    payload_preview: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Analysis {
    file_name: String,
    file_size: usize,
    packets: usize,
    captured_bytes: usize,
    duration_ms: u64,
    first_timestamp: Option<i64>,
    last_timestamp: Option<i64>,
    protocols: Vec<ProtocolStat>,
    endpoints: Vec<Endpoint>,
    conversations: Vec<Conversation>,
    observations: Vec<Observation>,
    warnings: Vec<String>,
    link_layer: String,
    packets_preview: Vec<PacketSummary>,
}

#[derive(Default)]
struct Counter {
    packets: usize,
    bytes: usize,
}
#[derive(Default)]
struct PacketInfo {
    source: String,
    destination: String,
    protocol: String,
    bytes: usize,
    timestamp_ms: i64,
    payload: Vec<u8>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
}

fn be16(x: &[u8]) -> u16 {
    u16::from_be_bytes([x[0], x[1]])
}
fn be32(x: &[u8]) -> u32 {
    u32::from_be_bytes([x[0], x[1], x[2], x[3]])
}
fn le32(x: &[u8]) -> u32 {
    u32::from_le_bytes([x[0], x[1], x[2], x[3]])
}
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect()
}
fn safe_timestamp(ms: i64) -> Option<i64> {
    // Captures with corrupt or unsupported timestamp units should not produce
    // dates outside the useful desktop capture range.
    (946684800000..=4102444800000).contains(&ms).then_some(ms)
}

fn decode_packet(data: &[u8], timestamp_ms: i64) -> Option<PacketInfo> {
    if data.len() < 14 {
        return None;
    }
    let ether_type = be16(&data[12..14]);
    let mut offset = 14;
    if ether_type == 0x8100 && data.len() >= 18 {
        offset = 18;
    }
    if data.len() < offset + 20 {
        return None;
    }
    let (source, destination, mut transport, mut header_len) = if ether_type == 0x0800 {
        let ihl = (data[offset] & 0x0f) as usize * 4;
        if ihl < 20 || data.len() < offset + ihl {
            return None;
        }
        let protocol = data[offset + 9];
        (
            format!(
                "{}.{}.{}.{}",
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15]
            ),
            format!(
                "{}.{}.{}.{}",
                data[offset + 16],
                data[offset + 17],
                data[offset + 18],
                data[offset + 19]
            ),
            protocol,
            offset + ihl,
        )
    } else if ether_type == 0x86dd && data.len() >= offset + 40 {
        let protocol = data[offset + 6];
        let fmt = |p: &[u8]| -> String {
            format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                be16(&p[0..2]),
                be16(&p[2..4]),
                be16(&p[4..6]),
                be16(&p[6..8]),
                be16(&p[8..10]),
                be16(&p[10..12]),
                be16(&p[12..14]),
                be16(&p[14..16])
            )
        };
        (
            fmt(&data[offset + 8..offset + 24]),
            fmt(&data[offset + 24..offset + 40]),
            protocol,
            offset + 40,
        )
    } else {
        return None;
    };
    let mut source_port = None;
    let mut destination_port = None;
    if (transport == 6 || transport == 17) && data.len() >= header_len + 4 {
        source_port = Some(be16(&data[header_len..header_len + 2]));
        destination_port = Some(be16(&data[header_len + 2..header_len + 4]));
        if transport == 6 && data.len() >= header_len + 13 {
            header_len += ((data[header_len + 12] >> 4) as usize) * 4;
        } else {
            header_len += 8;
        }
    }
    if header_len > data.len() {
        header_len = data.len();
    }
    let protocol = match transport {
        6 => match destination_port.or(source_port) {
            Some(80) | Some(8080) => "HTTP",
            Some(443) => "TLS",
            _ => "TCP",
        },
        17 => match destination_port.or(source_port) {
            Some(53) => "DNS",
            _ => "UDP",
        },
        1 => "ICMP",
        58 => "ICMPv6",
        _ => "Other",
    }
    .to_string();
    Some(PacketInfo {
        source,
        destination,
        protocol,
        bytes: data.len(),
        timestamp_ms,
        payload: data[header_len..].to_vec(),
        source_port,
        destination_port,
    })
}

fn parse_pcapng(data: &[u8]) -> Result<(Vec<PacketInfo>, String), String> {
    let mut packets = Vec::new();
    let mut link = "Ethernet".to_string();
    if data.len() < 4 {
        return Err("The file is too small to be a packet capture.".into());
    }
    if &data[0..4] == &[0xd4, 0xc3, 0xb2, 0xa1] || &data[0..4] == &[0xa1, 0xb2, 0xc3, 0xd4] {
        let little = data[0] == 0xd4;
        let read = |p: &[u8]| {
            if little {
                u32::from_le_bytes([p[0], p[1], p[2], p[3]])
            } else {
                be32(p)
            }
        };
        let mut pos = 24;
        while pos + 16 <= data.len() {
            let incl = read(&data[pos + 8..pos + 12]) as usize;
            let ts = (read(&data[pos..pos + 4]) as i64) * 1000
                + (read(&data[pos + 4..pos + 8]) as i64 / 1000);
            if pos + 16 + incl > data.len() {
                break;
            }
            if let Some(packet) = decode_packet(&data[pos + 16..pos + 16 + incl], ts) {
                packets.push(packet);
            }
            pos += 16 + incl + ((4 - incl % 4) % 4);
        }
        return Ok((packets, link));
    }
    let little = data.len() >= 12 && &data[8..12] == &[0x4d, 0x3c, 0x2b, 0x1a];
    let read32 = |p: &[u8]| if little { le32(p) } else { be32(p) };
    let mut pos = 0;
    while pos + 12 <= data.len() {
        let block_type = read32(&data[pos..pos + 4]);
        let length = read32(&data[pos + 4..pos + 8]) as usize;
        if length < 12 || pos + length > data.len() {
            break;
        }
        let block = &data[pos..pos + length];
        match block_type {
            0x00000001 => {
                link = "Ethernet".into();
            }
            0x00000006 if length >= 32 => {
                let timestamp =
                    ((read32(&block[12..16]) as i64) << 32) | read32(&block[16..20]) as i64;
                let captured = read32(&block[20..24]) as usize;
                let end = (28 + captured).min(block.len() - 4);
                if end > 28 {
                    if let Some(packet) = decode_packet(&block[28..end], timestamp / 1000) {
                        packets.push(packet);
                    }
                }
            }
            0x00000003 if length >= 16 => {
                let captured = read32(&block[12..16]) as usize;
                let end = (16 + captured).min(block.len() - 4);
                if end > 16 {
                    if let Some(packet) = decode_packet(&block[16..end], 0) {
                        packets.push(packet);
                    }
                }
            }
            _ => {}
        }
        pos += length;
    }
    if packets.is_empty() && data.len() > 28 {
        return Err("No Ethernet packets could be decoded from this capture.".into());
    }
    Ok((packets, link))
}

fn observation_for(packet: &PacketInfo) -> Option<Observation> {
    let lower = text(&packet.payload);
    if packet.protocol == "DNS" && packet.payload.len() >= 12 {
        return Some(Observation {
            kind: "dns".into(),
            title: "DNS traffic detected".into(),
            detail: format!(
                "{} queried {} in the capture",
                packet.source, packet.destination
            ),
        });
    }
    if packet.protocol == "HTTP"
        && (lower.starts_with("GET ") || lower.starts_with("POST ") || lower.contains("Host:"))
    {
        let host = lower
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("host:"))
            .unwrap_or("HTTP request");
        return Some(Observation {
            kind: "http".into(),
            title: "Readable HTTP request".into(),
            detail: format!(
                "{} → {} · {}",
                packet.source,
                packet.destination,
                host.trim()
            ),
        });
    }
    if packet.protocol == "TLS" && packet.payload.len() > 5 && packet.payload[0] == 22 {
        return Some(Observation {
            kind: "tls".into(),
            title: "Encrypted TLS session".into(),
            detail: format!(
                "TLS handshake between {} and {}",
                packet.source, packet.destination
            ),
        });
    }
    None
}

#[tauri::command]
fn analyze_capture(data: Vec<u8>, file_name: String, file_size: usize) -> Result<Analysis, String> {
    let (packets, link_layer) = parse_pcapng(&data)?;
    let mut protocols: HashMap<String, Counter> = HashMap::new();
    let mut endpoints: HashMap<String, Counter> = HashMap::new();
    let mut conversations: HashMap<(String, String, String), Counter> = HashMap::new();
    let mut observations = Vec::new();
    for packet in &packets {
        protocols
            .entry(packet.protocol.clone())
            .or_default()
            .add(packet.bytes);
        endpoints
            .entry(packet.source.clone())
            .or_default()
            .add(packet.bytes);
        endpoints
            .entry(packet.destination.clone())
            .or_default()
            .add(packet.bytes);
        let key = if packet.source <= packet.destination {
            (
                packet.source.clone(),
                packet.destination.clone(),
                packet.protocol.clone(),
            )
        } else {
            (
                packet.destination.clone(),
                packet.source.clone(),
                packet.protocol.clone(),
            )
        };
        conversations.entry(key).or_default().add(packet.bytes);
        if observations.len() < 12 {
            if let Some(item) = observation_for(packet) {
                if !observations
                    .iter()
                    .any(|x: &Observation| x.title == item.title)
                {
                    observations.push(item);
                }
            }
        }
    }
    let total = protocols.values().map(|x| x.bytes).sum::<usize>().max(1);
    let mut protocol_list: Vec<_> = protocols
        .into_iter()
        .map(|(name, c)| ProtocolStat {
            name,
            packets: c.packets,
            bytes: c.bytes,
            share: c.bytes as f64 * 100.0 / total as f64,
        })
        .collect();
    protocol_list.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    let mut endpoint_list: Vec<_> = endpoints
        .into_iter()
        .map(|(address, c)| Endpoint {
            role: if address.contains(':') || address.split('.').count() == 4 {
                "host".into()
            } else {
                "unknown".into()
            },
            address,
            packets: c.packets,
            bytes: c.bytes,
        })
        .collect();
    endpoint_list.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    let mut conversation_list: Vec<_> = conversations
        .into_iter()
        .map(|((source, destination, protocol), c)| Conversation {
            source,
            destination,
            protocol,
            packets: c.packets,
            bytes: c.bytes,
        })
        .collect();
    conversation_list.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    let first = packets
        .iter()
        .filter_map(|p| safe_timestamp(p.timestamp_ms))
        .min()
        .unwrap_or(0);
    let last = packets
        .iter()
        .filter_map(|p| safe_timestamp(p.timestamp_ms))
        .max()
        .unwrap_or(first);
    let packets_preview = packets
        .iter()
        .take(500)
        .enumerate()
        .map(|(index, packet)| PacketSummary {
            number: index + 1,
            timestamp: safe_timestamp(packet.timestamp_ms).unwrap_or(0),
            source: packet.source.clone(),
            destination: packet.destination.clone(),
            protocol: packet.protocol.clone(),
            bytes: packet.bytes,
            source_port: packet.source_port,
            destination_port: packet.destination_port,
            payload_preview: text(&packet.payload).chars().take(120).collect(),
        })
        .collect();
    let mut warnings = Vec::new();
    if packets.is_empty() {
        warnings.push("The capture contains no decodable Ethernet packets.".into());
    }
    if packets.iter().any(|p| p.protocol == "Other") {
        warnings.push("Some packets use unsupported or non-IP protocols.".into());
    }
    Ok(Analysis {
        file_name,
        file_size,
        packets: packets.len(),
        captured_bytes: packets.iter().map(|p| p.bytes).sum(),
        duration_ms: if first > 0 && last >= first {
            (last - first).min(86_400_000 * 365) as u64
        } else {
            0
        },
        first_timestamp: safe_timestamp(first),
        last_timestamp: safe_timestamp(last),
        protocols: protocol_list,
        endpoints: endpoint_list,
        conversations: conversation_list,
        observations,
        warnings,
        link_layer,
        packets_preview,
    })
}

impl Counter {
    fn add(&mut self, bytes: usize) {
        self.packets += 1;
        self.bytes += bytes;
    }
}

pub fn run() {
    #[cfg(target_os = "windows")]
    {
        if let Ok(executable) = std::env::current_exe() {
            if let Some(folder) = executable.parent() {
                let runtime = folder.join("WebView2Runtime");
                if runtime.is_dir() {
                    std::env::set_var("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", runtime);
                }
            }
        }
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![analyze_capture])
        .run(tauri::generate_context!())
        .expect("error while running WireView");
}
