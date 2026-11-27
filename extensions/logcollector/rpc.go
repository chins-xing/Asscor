package logcollector

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	apiv1 "github.com/chins-xing/asscor/api/v1"
)

const maxLine = 8 << 20 // 8 MiB per RPC request

type rpcRequest struct {
	ID     int             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

type configureParams struct {
	Path string `json:"path"`
}

type appendParams struct {
	Entry *apiv1.LogEntry `json:"entry"`
}

type appendBatchParams struct {
	Entries []*apiv1.LogEntry `json:"entries"`
}

// RunChild is the logcollector-mod entry point.
func RunChild() error {
	reader := bufio.NewReaderSize(os.Stdin, 1<<20)
	encoder := json.NewEncoder(os.Stdout)
	var w *Writer
	defer func() {
		if w != nil {
			w.Close()
		}
	}()
	for {
		line, err := reader.ReadBytes('\n')
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(line) > maxLine {
			return fmt.Errorf("request exceeds %d bytes", maxLine)
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_ = encoder.Encode(rpcResponse{ID: req.ID, Error: "bad json: " + err.Error()})
			continue
		}
		resp := rpcResponse{ID: req.ID}
		switch req.Method {
		case "configure":
			var p configureParams
			if err := json.Unmarshal(req.Params, &p); err != nil || p.Path == "" {
				resp.Error = "configure requires path"
				break
			}
			if w != nil {
				w.Close()
			}
			nw, err := NewWriter(p.Path)
			if err != nil {
				resp.Error = err.Error()
				break
			}
			w = nw
			resp.Result, _ = json.Marshal(map[string]string{"path": w.Path()})
		case "append":
			var p appendParams
			if err := json.Unmarshal(req.Params, &p); err != nil || w == nil {
				resp.Error = "append requires configured writer and entry"
				break
			}
			if err := w.Append(p.Entry); err != nil {
				resp.Error = err.Error()
			}
		case "append_batch":
			var p appendBatchParams
			if err := json.Unmarshal(req.Params, &p); err != nil || w == nil {
				resp.Error = "append_batch requires configured writer and entries"
				break
			}
			if err := w.AppendBatch(p.Entries); err != nil {
				resp.Error = err.Error()
			}
		case "log_path":
			path := ""
			if w != nil {
				path = w.Path()
			}
			resp.Result, _ = json.Marshal(map[string]string{"path": path})
		case "ping":
			resp.Result, _ = json.Marshal(map[string]string{"status": "ok"})
		case "sync":
			if w != nil {
				w.Sync()
			}
		case "shutdown":
			if w != nil {
				w.Close()
				w = nil
			}
			_ = encoder.Encode(resp)
			return nil
		default:
			resp.Error = "unknown method: " + req.Method
		}
		if err := encoder.Encode(resp); err != nil {
			return err
		}
	}
}
