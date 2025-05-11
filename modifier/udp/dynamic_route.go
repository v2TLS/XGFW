package udp

import (
	"errors"
	"math/rand"
	"net"
	"time"
	"strconv"

	"github.com/v2TLS/XGFW/modifier"
)

// GatewayConfig 定义每个出口网关的配置
type GatewayConfig struct {
	IP      string
	Port    int
	Percent int // 分流百分比
}

// DynamicRouteModifier 支持按百分比动态分流到不同出口
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
	return &dynamicRouteInstance{gateways: gateways, randSrc: rand.New(rand.NewSource(time.Now().UnixNano()))}, nil
}

type dynamicRouteInstance struct {
	gateways []GatewayConfig
	randSrc  *rand.Rand
}

// Process: 按百分比选择网关，转发UDP包。如果IP为0.0.0.0则表示直接放行（不修改数据包）。
func (i *dynamicRouteInstance) Process(data []byte) ([]byte, error) {
	idx := i.pickGatewayIndex()
	gw := i.gateways[idx]
	if gw.IP == "0.0.0.0" || gw.IP == "" {
		// 0.0.0.0 表示直接放行
		return data, nil
	}
	// 直接UDP发送到目标网关
	addr := net.JoinHostPort(gw.IP, strconv.Itoa(gw.Port))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, &modifier.ErrInvalidPacket{Err: err}
	}
	defer conn.Close()
	_, err = conn.Write(data)
	if err != nil {
		return nil, &modifier.ErrInvalidPacket{Err: err}
	}
	// 返回空，表示本地不再转发到公网
	return nil, nil
}

// pickGatewayIndex 按百分比随机选一个网关
func (i *dynamicRouteInstance) pickGatewayIndex() int {
	r := i.randSrc.Intn(100)
	acc := 0
	for idx, gw := range i.gateways {
		acc += gw.Percent
		if r < acc {
			return idx
		}
	}
	return len(i.gateways) - 1
}

// 确保接口实现
var _ modifier.Modifier = (*DynamicRouteModifier)(nil)
var _ modifier.UDPModifierInstance = (*dynamicRouteInstance)(nil)
