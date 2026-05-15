# Trustify

A private, client-side APK analyzer. Inspect Android applications directly in your browser without uploading files to a server.

## Features

- **Private**: All processing happens locally via WebAssembly. Your APKs never leave your device.
- **Deep Inspection**: View package metadata, permissions, activities, services, receivers, and providers.
- **Resource Extraction**: Read and extract `AndroidManifest.xml` and string resources.
- **Modern UI**: Sleek, minimalist design with native dark/light mode support.

## How it works

Trustify uses a WebAssembly-compiled engine to parse APK files on the fly. It leverages your browser's local processing power to handle binary XML decoding and resource extraction without needing a backend.

## Getting Started

Since the app is entirely static, you can run it with any local web server:

```bash
# Example using npx
npx serve .
```

Then open `http://localhost:3000` in your browser.

## Privacy

Trustify is built on the principle of local-first security. It does not collect telemetry, track usage, or store your analyzed data.
