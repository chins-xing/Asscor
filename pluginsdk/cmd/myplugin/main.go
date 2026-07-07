// This is a self-contained example of an ASSCOR plugin built with the pluginsdk.
// Build: go build -o myplugin ./cmd/myplugin/
// Install: copy myplugin binary + extension.json into the ASSCOR extensions directory.
//
// The plugin communicates with the ASSCOR kernel via JSON-RPC over stdin/stdout.
// It requires zero imports from the ASSCOR codebase — only the pluginsdk module.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/asscor/pluginsdk"
)

type MyPlugin struct {
	name string
}

func (p *MyPlugin) Init(config map[string]string) error {
	p.name = config["name"]
	if p.name == "" {
		p.name = "myplugin"
	}
	fmt.Fprintf(os.Stderr, "[%s] plugin initialized at %s\n", p.name, time.Now().Format(time.RFC3339))
	return nil
}

func (p *MyPlugin) HandleRequest(method string, params json.RawMessage) (json.RawMessage, error) {
	switch method {
	case "status":
		return json.RawMessage(fmt.Sprintf(`{"plugin":"%s","status":"running","time":"%s"}`,
			p.name, time.Now().Format(time.RFC3339))), nil
	case "health":
		return json.RawMessage(`{"healthy":true}`), nil
	default:
		return nil, fmt.Errorf("unknown method: %s", method)
	}
}

func (p *MyPlugin) Shutdown() error {
	fmt.Fprintf(os.Stderr, "[%s] plugin shutting down\n", p.name)
	return nil
}

func main() {
	pluginsdk.Serve(&MyPlugin{})
}
