package agent

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	apiv1 "github.com/asscor/asscor/api/v1"
)

type Client struct {
	addr      string
	tlsConfig *tls.Config
	conn      net.Conn
	br        *bufio.Reader
	mu        sync.Mutex
	deadline  time.Duration
	seq       int64
}

func NewClient(addr string, tlsConfig *tls.Config) *Client {
	return &Client{
		addr:      addr,
		tlsConfig: tlsConfig,
		deadline:  30 * time.Second,
	}
}

func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.br = nil
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}

	var err error
	if c.tlsConfig != nil {
		c.conn, err = tls.DialWithDialer(dialer, "tcp", c.addr, c.tlsConfig)
	} else {
		c.conn, err = dialer.Dial("tcp", c.addr)
	}

	if err != nil {
		return fmt.Errorf("connect to %s: %w", c.addr, err)
	}

	c.br = bufio.NewReaderSize(c.conn, 256*1024)
	return nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.br = nil
		return err
	}
	return nil
}

func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

func (c *Client) Register(req *apiv1.RegisterRequest) (*apiv1.RegisterResponse, error) {
	var resp apiv1.RegisterResponse
	err := c.call("ASSCOR.v1.KernelService", "Register", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Heartbeat(req *apiv1.HeartbeatRequest) (*apiv1.HeartbeatResponse, error) {
	var resp apiv1.HeartbeatResponse
	err := c.call("ASSCOR.v1.KernelService", "Heartbeat", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Call(service, method string, req, resp interface{}) error {
	return c.call(service, method, req, resp)
}

func (c *Client) call(service, method string, req, resp interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	c.seq++
	reqData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	envelope := map[string]interface{}{
		"service": service,
		"method":  method,
		"payload": json.RawMessage(reqData),
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	c.conn.SetWriteDeadline(time.Now().Add(c.deadline))
	data = append(data, '\n')
	for written := 0; written < len(data); {
		n, err := c.conn.Write(data[written:])
		if err != nil {
			return fmt.Errorf("write: %w", err)
		}
		written += n
	}

	c.conn.SetReadDeadline(time.Now().Add(c.deadline))
	line, err := c.br.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}

	var respEnv struct {
		Status  string          `json:"status"`
		Payload json.RawMessage `json:"payload"`
		Error   string          `json:"error,omitempty"`
	}
	if err := json.Unmarshal(line, &respEnv); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	if respEnv.Status == "error" || respEnv.Error != "" {
		return fmt.Errorf("rpc error: %s", respEnv.Error)
	}

	if respEnv.Payload != nil {
		if err := json.Unmarshal(respEnv.Payload, resp); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
	}

	return nil
}