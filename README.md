# Zantoras

Tamper-proof evidence infrastructure for the enterprise.

## Replay Engine

The Replay Engine is an auditor tool for verifying evidence chain integrity.

### Download

Download the latest version for your platform from [Releases](https://github.com/zantoras01/zantoras/releases).

- **Windows**: `zantoras-replay-windows-amd64.exe`
- **macOS (Intel)**: `zantoras-replay-macos-amd64`
- **macOS (Apple Silicon)**: `zantoras-replay-macos-arm64`
- **Linux**: `zantoras-replay-linux-amd64`

### Usage

```bash
# Verify an evidence export
zantoras-replay verify evidence-export.json
```

### What it does

1. Loads the evidence export file from Zantoras Evidence Engine
2. Verifies each blob's cryptographic hash
3. Verifies the chain linkage (each blob links to previous)
4. Verifies the overall chain hash
5. Reports VERIFIED or TAMPERED

## Evidence Engine

The Evidence Engine dashboard is available at [engine.zantoras.com](https://engine.zantoras.com)

## Links

- [Website](https://zantoras.com)
- [Dashboard](https://engine.zantoras.com)
