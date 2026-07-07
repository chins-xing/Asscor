# ASSCOR Plugin SDK

Build independent ASSCOR plugins that communicate via JSON-RPC over stdin/stdout.
Zero imports from the ASSCOR codebase — only this SDK module.

## Quick Start

```bash
# 1. Copy the example
cp -r cmd/myplugin cmd/yourplugin

# 2. Edit cmd/yourplugin/main.go — implement your logic in HandleRequest()

# 3. Build (produces a standalone binary)
cd cmd/yourplugin && go build -o yourplugin .

# 4. Package
cp yourplugin extension.json /opt/asscor/extensions/yourplugin/

# 5. Install into ASSCOR
asscor> source deploy yourplugin
```

## Architecture (Low Coupling)

```
ASSCOR Kernel                    Your Plugin (separate process)
      │                                    │
      │  JSON-RPC 2.0 over stdin/stdout    │
      │←──────────────────────────────────→│
      │  {"jsonrpc":"2.0","method":"...","id":"1"}  │
      │  {"jsonrpc":"2.0","id":"1","result":{...}}   │
      │                                    │
```

## Plugin Interface

```go
type Plugin interface {
    Init(config map[string]string) error
    HandleRequest(method string, params json.RawMessage) (json.RawMessage, error)
    Shutdown() error
}
```

## Built-in Methods (reserved)
- `init` — called once at plugin start, passes custom_config
- `shutdown` — called before process termination

## Security
- Plugin runs as separate process (no shared memory with kernel)
- Only stdin/stdout communication channel
- Integrity verified via SHA-256 checksum in extension.json
- Resource limits managed via systemd scoping
