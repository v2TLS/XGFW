package udp

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/v2TLS/XGFW/modifier"
)

type RedirectModifier struct{}

func (m *RedirectModifier) Name() string {
	return "redirect"
}

func (m *RedirectModifier) New(args map[string]interface{}) (modifier.Instance, error) {
	ip, _ := args["ip"].(string)
	port := 0
	if p, ok := args["port"].(int); ok {
		port = p
	} else if pf, ok := args["port"].(float64); ok {
		port = int(pf)
	}
	if ip == "" || port == 0 {
		return nil, &modifier.ErrInvalidArgs{Err: errors.New("ip and port required")}
	}
	timeout := 3 * time.Second
	if t, ok := args["timeout"].(int); ok && t > 0 {
		timeout = time.Duration(t) * time.Second
	} else if tf, ok := args["timeout"].(float64); ok && tf > 0 {
		timeout = time.Duration(int(tf)) * time.Second
	}
	if tp, ok := args["type"].(string); ok && tp == "tcp" {
		return &redirectTCPInstance{ip: ip, port: port, timeout: timeout}, nil
	}
	return &redirectUDPInstance{ip: ip, port: port, timeout: timeout}, nil
}

// UDP实现
type redirectUDPInstance struct {
	ip      string
	port    int
	timeout time.Duration
}

var _ modifier.UDPModifierInstance = (*redirectUDPInstance)(nil)

func (i *redirectUDPInstance) Process(data []byte) ([]byte, error) {
	addr := net.JoinHostPort(i.ip, itoa(i.port))
	conn, err := net.DialTimeout("udp", addr, i.timeout)
	if err != nil {
		return nil, &modifier.ErrInvalidPacket{Err: err}
	}
	defer conn.Close()
	_, err = conn.Write(data)
	if err != nil {
		return nil, &modifier.ErrInvalidPacket{Err: err}
	}
	return nil, nil
}

// TCP实现
type redirectTCPInstance struct {
	ip      string
	port    int
	timeout time.Duration
}

var _ modifier.TCPModifierInstance = (*redirectTCPInstance)(nil)

func (i *redirectTCPInstance) Process(data []byte, direction bool) ([]byte, error) {
	addr := net.JoinHostPort(i.ip, itoa(i.port))
	conn, err := net.DialTimeout("tcp", addr, i.timeout)
	if err != nil {
		return nil, &modifier.ErrInvalidPacket{Err: err}
	}
	defer conn.Close()
	_, err = conn.Write(data)
	if err != nil {
		return nil, &modifier.ErrInvalidPacket{Err: err}
	}
	return nil, nil
}

func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
