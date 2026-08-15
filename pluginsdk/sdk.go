// Package pluginsdk provides the interface and runtime for building independent
// ASSCOR plugins that communicate via JSON-RPC over stdin/stdout. Plugins written
// with this SDK can be registered as `custom` extensions and managed via the
// ASSCOR ExtensionManager without modifying or recompiling the core binary.
//
// Architecture (low coupling):
//   - Plugin runs as a separate process (no shared memory)
//   - Communication via JSON-RPC 2.0 over stdin/stdout
//   - Plugin declares its capabilities in a manifest (extension.json)
//   - ASSCOR ExtensionManager discovers, installs, starts, and stops plugins
//
// Security:
//   - Plugins run in sandboxed processes (no kernel memory access)
//   - Only stdin/stdout communication channel (no network by default)
//   - Configurable timeout, memory limits via systemd scoping
//   - Integrity verified via SHA-256 checksum in manifest
package pluginsdk

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
)

// RPCPlugin is the interface that all ASSCOR RPC-based plugins must implement.
// Note: this is distinct from kernel.Plugin (compiled-in, in-process).
// RPCPlugin communicates via JSON-RPC over stdin/stdout as a separate OS process.
type RPCPlugin interface {
	// Init is called once after the plugin process starts. The config parameter
	// contains the plugin-specific configuration from extension.json custom_config.
	Init(config map[string]string) error

	// HandleRequest processes an RPC request and returns a response.
	// The method parameter indicates the operation (e.g. "assess", "status").
	HandleRequest(method string, params json.RawMessage) (json.RawMessage, error)

	// Shutdown is called when the plugin process should gracefully stop.
	Shutdown() error
}

// Serve runs the JSON-RPC stdin/stdout loop for the given plugin.
// It should be called from the plugin's main() function.
//
// Example:
//
//	func main() {
//	    pluginsdk.Serve(&MyPlugin{})
//	}
func Serve(p RPCPlugin) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "plugin fatal panic: %v\n", r)
			buf := make([]byte, 8192)
			n := runtime.Stack(buf, false)
			fmt.Fprintf(os.Stderr, "%s\n", buf[:n])
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 2*1024*1024)

	encoder := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			writeError(encoder, "", -32700, "parse error: "+err.Error())
			continue
		}

		var result json.RawMessage

		if err := func() (rerr error) {
			defer func() {
				if r := recover(); r != nil {
					rerr = fmt.Errorf("panic: %v", r)
				}
			}()
			switch req.Method {
			case "init":
				var cfg map[string]string
				json.Unmarshal(req.Params, &cfg)
				if rerr = p.Init(cfg); rerr == nil {
					result = json.RawMessage(`{"status":"ok"}`)
				}
			case "shutdown":
				if rerr = p.Shutdown(); rerr == nil {
					writeResponse(encoder, req.ID, json.RawMessage(`{"status":"ok"}`))
					return
				}
			default:
				result, rerr = p.HandleRequest(req.Method, req.Params)
			}
			return rerr
		}(); err != nil {
			writeError(encoder, req.ID, -32603, err.Error())
			continue
		}

		writeResponse(encoder, req.ID, result)
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "plugin scanner error: %v\n", err)
	}
}

const (
	ErrParse    = -32700 // JSON-RPC standard: parse error
	ErrInternal = -32603 // JSON-RPC standard: internal error
	ErrMethodNF = -32601 // JSON-RPC standard: method not found
	ErrApp      = -32000 // Implementation-defined: application error
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeResponse(w *json.Encoder, id string, result json.RawMessage) {
	err := w.Encode(rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugin write error: %v\n", err)
	}
}

func writeError(w *json.Encoder, id string, code int, msg string) {
	if id == "" {
		id = "null"
	}
	err := w.Encode(rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: msg},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "plugin write error: %v\n", err)
	}
}
