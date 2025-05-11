package udp

import (
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/v2TLS/XGFW/modifier"
)

// RedirectModifier 用于将 UDP 包转发到指定IP和端口
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
	return &redirectModifierInstance{ip: ip, port: port, timeout: timeout}, nil
}

type redirectModifierInstance struct {
	ip      string
	port    int
	timeout time.Duration
}

// Process 将收到的数据转发到目标IP和端口，不修改数据内容
func (i *redirectModifierInstance) Process(data []byte) ([]byte, error) {
    addr := net.JoinHostPort(i.ip, strconv.Itoa(i.port))
    conn, err := net.DialTimeout("udp", addr, i.timeout)
	if err != nil {
		return nil, &modifier.ErrInvalidPacket{Err: err}
	}
	defer conn.Close()
	_, err = conn.Write(data)
	if err != nil {
		return nil, &modifier.ErrInvalidPacket{Err: err}
	}
	// 返回 nil 表示本地不再转发到原目标
	return nil, nil
}

var _ modifier.Modifier = (*RedirectModifier)(nil)
var _ modifier.UDPModifierInstance = (*redirectModifierInstance)(nil)
