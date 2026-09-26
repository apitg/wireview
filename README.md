# WireView

WireView is an offline desktop application that turns PCAP and PCAPNG captures into a readable network overview. It shows traffic volume, protocols, endpoints, conversations, packet timing, and lightweight DNS/HTTP/TLS observations without storing captures, settings, or history.

## Development

```bash
npm install
npm run tauri dev
```

The desktop build requires the Rust toolchain and the platform prerequisites listed in the [Tauri guide](https://tauri.app/start/prerequisites/).

## Production builds

```bash
npm run tauri build
```

GitHub Actions builds portable Windows installers and Linux AppImages on every push and pull request. Version tags additionally create a GitHub Release with both artifacts attached.
