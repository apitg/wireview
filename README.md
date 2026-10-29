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

GitHub Actions builds a portable Windows ZIP and a Linux AppImage on every push and pull request. Version tags additionally create a GitHub Release with both artifacts attached.

## Release assets

The Windows CI artifact is `wireview-portable.zip`. Its root contains `wireview.exe` and a `WebView2Runtime/` folder containing the bundled Chromium-based WebView2 runtime. Keep the folder intact when moving or launching the executable; it does not require WebView2 to be installed system-wide. Linux builds are distributed as an AppImage.

Application branding assets live in `src-tauri/icons/`. Replace `icon.png` and `icon.ico` with the project-owned artwork before publishing a public release; the Tauri configuration uses those files for the window and bundled application icon.
