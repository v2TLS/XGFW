package udp

import (
	"errors"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/v2TLS/XGFW/modifier"
)

type GatewayConfig struct {
	IP      string
	Port    int
	Percent int // 分流百分比
}

type DynamicRouteModifier struct{}

func (m *DynamicRouteModifier) Name() string {
	return "dynamic_route"
}

func (m *DynamicRouteModifier) New(args map[string]interface{}) (modifier.Instance, error) {
	gs, ok := args["gateways"].([]interface{})
	if !ok || len(gs) == 0 {
		return nil, &modifier.ErrInvalidArgs{Err: errors.New("missing gateways")}
	}
	var gateways []GatewayConfig
	total := 0
	for _, g := range gs {
		gmap, ok := g.(map[string]interface{})
		if !ok {
			continue
		}
		ip, _ := gmap["ip"].(string)
		port := 0
		if p, ok := gmap["port"].(int); ok {
			port = p
		} else if pf, ok := gmap["port"].(float64); ok {
			port = int(pf)
		}
		percent := 0
		if pc, ok := gmap["percent"].(int); ok {
			percent = pc
		} else if pcf, ok := gmap["percent"].(float64); ok {
			percent = int(pcf)
		}
		gateways = append(gateways, GatewayConfig{IP: ip, Port: port, Percent: percent})
		total += percent
	}
	if total != 100 {
		return nil, &modifier.ErrInvalidArgs{Err: errors.New("total percent must be 100")}
	}
	// 根据 type 返回 UDP 或 TCP 实例
	if t, ok := args["type"].(string); ok && t == "tcp" {
		return &dynamicRouteTCPInstance{gateways: gateways, randSrc: rand.New(rand.NewSource(time.Now().UnixNano()))}, nil
	}
	return &dynamicRouteUDPInstance{gateways: gateways, randSrc: rand.New(rand.NewSource(time.Now().UnixNano()))}, nil
}

// UDP 实现
type dynamicRouteUDPInstance struct {
	gateways []GatewayConfig
	randSrc  *rand.Rand
}

var _ modifier.UDPModifierInstance = (*dynamicRouteUDPInstance)(nil)

func (i *dynamicRouteUDPInstance) Process(data []byte) ([]byte, error) {
	return routeAndSend(i.gateways, i.randSrc, data, "udp")
}

// TCP 实现
type dynamicRouteTCPInstance struct {
	gateways []GatewayConfig
	randSrc  *rand.Rand
}

var _ modifier.TCPModifierInstance = (*dynamicRouteTCPInstance)(nil)

func (i *dynamicRouteTCPInstance) Process(data []byte, direction bool) ([]byte, error) {
	return routeAndSend(i.gateways, i.randSrc, data, "tcp")
}

// 公用逻辑
func routeAndSend(gateways []GatewayConfig, randSrc *rand.Rand, data []byte, proto string) ([]byte, error) {
	idx := pickGatewayIndex(gateways, randSrc)
	gw := gateways[idx]
	if gw.IP == "0.0.0.0" || gw.IP == "" {
		return data, nil // 直接放行
	}
	addr := net.JoinHostPort(gw.IP, strconv.Itoa(gw.Port))
	conn, err := net.Dial(proto, addr)
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

func pickGatewayIndex(gateways []GatewayConfig, randSrc *rand.Rand) int {
	r := randSrc.Intn(100)
	acc := 0
	for idx, gw := range gateways {
		acc += gw.Percent
		if r < acc {
			return idx
		}
	}
	return len(gateways) - 1
}
