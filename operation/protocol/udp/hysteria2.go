package udp

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/v2TLS/XGFW/operation"
	"github.com/v2TLS/XGFW/operation/protocol/internal"
	"github.com/v2TLS/XGFW/operation/protocol/udp/internal/quic"
	"github.com/v2TLS/XGFW/operation/utils"
)

// 常量定义
const (
	hysteria2MinDataSize    = 41
	hysteria2TestPortCount  = 10
	hysteria2ServerPortMin  = 20000
	hysteria2ServerPortMax  = 50000
	hysteria2HighTrafficBytes = 500 * 1024 * 1024 / 8 // 500 Mb = 62.5 MB
	hysteria2TenMinutes       = 10 * time.Minute
	hysteria2PortRequestTimeout = 1 * time.Second

	hysteria2PositiveScore   = 2
	hysteria2NegativeScore   = 1
	hysteria2BlockThreshold  = 20

	hysteria2ResultFile = "hysteria2_result.json"
	hysteria2BlockFile  = "hysteria2_block.json"
	hysteria2BasePath   = "/var/log/xgfw"
)

// 持久化相关结构和全局变量
type Hysteria2IPStats struct {
	IP        string    `json:"ip"`
	Score     int       `json:"score"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type Hysteria2Results struct {
	IPList []Hysteria2IPStats `json:"ip_list"`
	mu     sync.Mutex
}

var (
	hysteria2Results     *Hysteria2Results
	hysteria2BlockedIPs  map[string]struct{}
	hysteria2ResultMutex sync.RWMutex
	hysteria2Initialized bool
)

// 确保接口实现
var (
	_ analyzer.UDPAnalyzer = (*Hysteria2Analyzer)(nil)
	_ analyzer.UDPStream   = (*hysteria2Stream)(nil)
)

// Hysteria2Analyzer 实现 analyzer.UDPAnalyzer 接口
type Hysteria2Analyzer struct{}

func (a *Hysteria2Analyzer) Name() string {
	return "hysteria2-detector"
}

func (a *Hysteria2Analyzer) Limit() int {
	return 0
}

func (a *Hysteria2Analyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	serverIP := info.DstIP.String()
	serverPort := int(info.DstPort)

	return &hysteria2Stream{
		logger:        logger,
		startTime:     time.Now(),
		serverIP:      serverIP,
		serverPort:    serverPort,
		closeComplete: make(chan struct{}),
		randGen:       rand.New(rand.NewSource(time.Now().UnixNano())),
		info:          info,
	}
}

// hysteria2Stream 实现 analyzer.UDPStream 接口
type hysteria2Stream struct {
	logger       analyzer.Logger
	packetCount  int
	totalBytes   int
	startTime    time.Time
	sni          string
	serverIP     string
	serverPort   int
	mutex        sync.Mutex
	blocked      bool
	score        int
	randGen      *rand.Rand
	closeOnce    sync.Once
	closeComplete chan struct{}
	isQuicGo     bool // 是否为quic-go指纹
	info         analyzer.UDPInfo // 用于获取源IP
}

// 初始化持久化统计
func initHysteria2Stats() error {
	if hysteria2Initialized {
		return nil
	}
	hysteria2ResultMutex.Lock()
	defer hysteria2ResultMutex.Unlock()
	if hysteria2Initialized {
		return nil
	}
	if err := os.MkdirAll(hysteria2BasePath, 0755); err != nil {
		return err
	}
	hysteria2Results = &Hysteria2Results{
		IPList: make([]Hysteria2IPStats, 0),
	}
	hysteria2BlockedIPs = make(map[string]struct{})

	resultPath := filepath.Join(hysteria2BasePath, hysteria2ResultFile)
	if data, err := os.ReadFile(resultPath); err == nil {
		_ = json.Unmarshal(data, &hysteria2Results.IPList)
	}
	blockPath := filepath.Join(hysteria2BasePath, hysteria2BlockFile)
	if data, err := os.ReadFile(blockPath); err == nil {
		var blockedList []string
		_ = json.Unmarshal(data, &blockedList)
		for _, ip := range blockedList {
			hysteria2BlockedIPs[ip] = struct{}{}
		}
	}
	hysteria2Initialized = true
	return nil
}

// 更新IP统计
func updateHysteria2IPStats(ip string, isPositive bool) error {
	if err := initHysteria2Stats(); err != nil {
		return err
	}
	hysteria2Results.mu.Lock()
	defer hysteria2Results.mu.Unlock()

	if _, blocked := hysteria2BlockedIPs[ip]; blocked {
		return nil
	}
	now := time.Now()
	var found bool
	for i := range hysteria2Results.IPList {
		if hysteria2Results.IPList[i].IP == ip {
			if isPositive {
				hysteria2Results.IPList[i].Score += hysteria2PositiveScore
			} else {
				hysteria2Results.IPList[i].Score = maxHysteria2(0, hysteria2Results.IPList[i].Score-hysteria2NegativeScore)
			}
			hysteria2Results.IPList[i].LastSeen = now
			found = true
			if hysteria2Results.IPList[i].Score >= hysteria2BlockThreshold {
				_ = addHysteria2ToBlockList(ip)
			}
			break
		}
	}
	if !found && isPositive {
		hysteria2Results.IPList = append(hysteria2Results.IPList, Hysteria2IPStats{
			IP:        ip,
			Score:     hysteria2PositiveScore,
			FirstSeen: now,
			LastSeen:  now,
		})
	}
	return saveHysteria2Results()
}

// 添加IP到阻断名单
func addHysteria2ToBlockList(ip string) error {
	hysteria2BlockedIPs[ip] = struct{}{}
	blockPath := filepath.Join(hysteria2BasePath, hysteria2BlockFile)
	var blockedList []string
	if data, err := os.ReadFile(blockPath); err == nil {
		_ = json.Unmarshal(data, &blockedList)
	}
	if !containsHysteria2(blockedList, ip) {
		blockedList = append(blockedList, ip)
	}
	data, err := json.MarshalIndent(blockedList, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(blockPath, data, 0644)
}

// 保存结果
func saveHysteria2Results() error {
	data, err := json.MarshalIndent(hysteria2Results.IPList, "", "  ")
	if err != nil {
		return err
	}
	resultPath := filepath.Join(hysteria2BasePath, hysteria2ResultFile)
	return os.WriteFile(resultPath, data, 0644)
}

func containsHysteria2(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func maxHysteria2(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Feed 处理每个UDP包
func (s *hysteria2Stream) Feed(rev bool, data []byte) (*analyzer.PropUpdate, bool) {
	srcIP := s.info.SrcIP.String()
	if err := initHysteria2Stats(); err == nil {
		hysteria2ResultMutex.RLock()
		_, blocked := hysteria2BlockedIPs[srcIP]
		hysteria2ResultMutex.RUnlock()
		if blocked {
			return &analyzer.PropUpdate{
				Type: analyzer.PropUpdateReplace,
				M: analyzer.PropMap{
					"blocked": true,
					"reason":  "hysteria2-threshold-exceed",
					"score":   s.score,
				},
			}, true
		}
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 如果已经被阻断
	if s.blocked {
		_ = updateHysteria2IPStats(srcIP, true)
		return &analyzer.PropUpdate{
			Type: analyzer.PropUpdateReplace,
			M: analyzer.PropMap{
				"blocked": true,
				"reason":  "hysteria2-threshold-exceed",
				"score":   s.score,
			},
		}, true
	}

	if !s.isQUIC(data) {
		_ = updateHysteria2IPStats(srcIP, false)
		return nil, false
	}

	s.packetCount++
	s.totalBytes += len(data)

	if rev {
		return nil, false
	}

	// 解析 QUIC ClientHello
	pl, err := quic.ReadCryptoPayload(data)
	if err != nil || len(pl) < 4 {
		_ = updateHysteria2IPStats(srcIP, false)
		return nil, false
	}
	if pl[0] != internal.TypeClientHello {
		_ = updateHysteria2IPStats(srcIP, false)
		return nil, false
	}
	chLen := int(pl[1])<<16 | int(pl[2])<<8 | int(pl[3])
	if chLen < hysteria2MinDataSize {
		_ = updateHysteria2IPStats(srcIP, false)
		return nil, false
	}
	m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4:]})
	if m == nil {
		_ = updateHysteria2IPStats(srcIP, false)
		return nil, false
	}

	// 提取 SNI
	serverNameRaw, ok := m["ServerName"]
	if ok {
		if sn, ok2 := serverNameRaw.(string); ok2 {
			s.sni = sn
		}
	}

	// 检查是否为 golang 的 quic-go 指纹
	if isQuicGoFingerprint(m) {
		s.isQuicGo = true
	}

	// 分数评估
	if s.isQuicGo {
		s.score += hysteria2PositiveScore
	} else {
		if s.score > 0 {
			s.score -= hysteria2NegativeScore
			if s.score < 0 {
				s.score = 0
			}
		}
	}

	if s.score >= hysteria2BlockThreshold {
		s.blocked = true
		_ = updateHysteria2IPStats(srcIP, true)
		return &analyzer.PropUpdate{
			Type: analyzer.PropUpdateReplace,
			M: analyzer.PropMap{
				"blocked": true,
				"reason":  "hysteria2-threshold-exceed",
				"score":   s.score,
			},
		}, true
	}

	// 统计分数
	if s.score > 0 {
		_ = updateHysteria2IPStats(srcIP, true)
	} else {
		_ = updateHysteria2IPStats(srcIP, false)
	}

	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateMerge,
		M:    analyzer.PropMap{"req": m},
	}, true
}

// isQUIC 检测流量是否为 QUIC 流量
func (s *hysteria2Stream) isQUIC(data []byte) bool {
	const quicInvalidCountThreshold = 4
	invalidCount := 0

	pl, err := quic.ReadCryptoPayload(data)
	if err != nil || len(pl) < 4 {
		invalidCount++
		return invalidCount < quicInvalidCountThreshold
	}
	if pl[0] != internal.TypeClientHello {
		invalidCount++
		return invalidCount < quicInvalidCountThreshold
	}
	chLen := int(pl[1])<<16 | int(pl[2])<<8 | int(pl[3])
	if chLen < hysteria2MinDataSize {
		invalidCount++
		return invalidCount < quicInvalidCountThreshold
	}
	m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4:]})
	if m == nil {
		invalidCount++
		return invalidCount < quicInvalidCountThreshold
	}
	return true
}

// Close 在流结束时再返回统计信息或者已封锁信息
func (s *hysteria2Stream) Close(limited bool) *analyzer.PropUpdate {
	s.closeOnce.Do(func() {
		close(s.closeComplete)
	})
	s.mutex.Lock()
	defer s.mutex.Unlock()
	srcIP := s.info.SrcIP.String()
	blocked := s.blocked || (s.score >= hysteria2BlockThreshold)
	if blocked {
		s.blocked = true
		_ = updateHysteria2IPStats(srcIP, true)
		return &analyzer.PropUpdate{
			Type: analyzer.PropUpdateReplace,
			M: analyzer.PropMap{
				"blocked": true,
				"reason":  "hysteria2-threshold-exceed",
				"score":   s.score,
			},
		}
	}
	if s.score > 0 {
		_ = updateHysteria2IPStats(srcIP, true)
	} else {
		_ = updateHysteria2IPStats(srcIP, false)
	}
	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M: analyzer.PropMap{
			"packetCount":    s.packetCount,
			"totalBytes":     s.totalBytes,
			"elapsedSeconds": time.Since(s.startTime).Seconds(),
			"sni":            s.sni,
			"score":          s.score,
			"blocked":        false,
		},
	}
}

// checkServerResponses/isQuicGoFingerprint 复用原有函数
func checkServerResponses(ip string, randGen *rand.Rand) (bool, error) {
	ports, err := selectRandomPorts(hysteria2ServerPortMin, hysteria2ServerPortMax, hysteria2TestPortCount, randGen)
	if err != nil {
		return false, err
	}

	var wg sync.WaitGroup
	responseChan := make(chan string, hysteria2TestPortCount)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			resp, err := sendUDPRequest(ip, p, []byte("test"))
			if err == nil {
				responseChan <- resp
			}
		}(port)
	}

	wg.Wait()
	close(responseChan)

	responses := make([]string, 0, hysteria2TestPortCount)
	for resp := range responseChan {
		responses = append(responses, resp)
	}
	counts := make(map[string]int)
	for _, r := range responses {
		counts[r]++
	}
	for _, count := range counts {
		if count >= 7 {
			return true, nil
		}
	}
	return false, nil
}

func selectRandomPorts(min, max, n int, randGen *rand.Rand) ([]int, error) {
	if max < min || n <= 0 || (max-min+1) < n {
		return nil, errors.New("invalid port range or count")
	}

	ports := make(map[int]struct{})
	for len(ports) < n {
		p := randGen.Intn(max-min+1) + min
		ports[p] = struct{}{}
	}

	selected := make([]int, 0, n)
	for p := range ports {
		selected = append(selected, p)
	}
	return selected, nil
}

func sendUDPRequest(ip string, port int, message []byte) (string, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("udp", addr, hysteria2PortRequestTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(hysteria2PortRequestTimeout))
	_, err = conn.Write(message)
	if err != nil {
		return "", err
	}
	conn.SetReadDeadline(time.Now().Add(hysteria2PortRequestTimeout))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// isQuicGoFingerprint 判断 m 是否为 golang quic-go 的指纹
func isQuicGoFingerprint(m map[string]interface{}) bool {
	// quic-go 的 ClientHello 特征，参见 brutal.go
	if suites, ok := m["CipherSuites"].([]interface{}); ok && len(suites) >= 3 {
		expected := []uint16{0x1301, 0x1302, 0x1303}
		matched := true
		for i := 0; i < 3; i++ {
			var v uint16
			switch val := suites[i].(type) {
			case uint16:
				v = val
			case int:
				v = uint16(val)
			default:
				matched = false
			}
			if v != expected[i] {
				matched = false
			}
		}
		if matched {
			if groups, ok2 := m["SupportedGroups"].([]interface{}); ok2 && len(groups) >= 1 {
				for _, g := range groups {
					gv := 0
					switch t := g.(type) {
					case int:
						gv = t
					case uint16:
						gv = int(t)
					}
					if gv == 0x1d {
						if alpns, ok3 := m["ALPNs"].([]interface{}); ok3 {
							for _, a := range alpns {
								if s, ok4 := a.(string); ok4 && (s == "h3" || s == "h3-29" || s == "h3-32") {
									if _, ok5 := m["QUICTransportParameters"]; ok5 {
										return true
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return false
}
