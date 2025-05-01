package udp

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/v2TLS/XGFW/operation"
	"github.com/v2TLS/XGFW/operation/protocol/internal"
	"github.com/v2TLS/XGFW/operation/protocol/udp/internal/quic"
	"github.com/v2TLS/XGFW/operation/utils"
)

// 常量
const (
	brutalInvalidCountThreshold = 4

	positiveScoreIncrement = 2  // 阳性时加分
	negativeScoreDecrement = 1  // 阴性时减分，不可减至负数
	blockThreshold         = 20 // 分数大于此值则封锁

	intervalCount      = 5                     // 需要收集的区间数量
	intervalDuration   = 10 * time.Millisecond // 每个区间持续时间
	intervalStartChance = 0.01                 // 每次 Feed 启动区间的随机概率

	UDPResultFile = "brutal_result.json"
	UDPBlockFile  = "brutal_block.json"
	UDPBasePath   = "/var/log/xgfw"
)

// UDPIPStats 记录单个IP的统计信息
type UDPIPStats struct {
	IP        string    `json:"ip"`
	Score     int       `json:"score"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// BrutalResults 记录所有IP统计信息
type BrutalResults struct {
	IPList []UDPIPStats `json:"ip_list"`
	mu     sync.Mutex
}

var (
	udpResults     *BrutalResults
	udpBlockedIPs  map[string]struct{}
	udpResultMutex sync.RWMutex
	udpInitialized bool
)

// 确保实现接口
var (
	_ analyzer.UDPAnalyzer = (*BrutalAnalyzer)(nil)
	_ analyzer.UDPStream   = (*brutalStream)(nil)
)

// BrutalAnalyzer 实现 analyzer.UDPAnalyzer
type BrutalAnalyzer struct{}

func (a *BrutalAnalyzer) Name() string {
	return "brutal"
}

func (a *BrutalAnalyzer) Limit() int {
	return 0
}

func (a *BrutalAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return &brutalStream{
		logger: logger,
		score:  0,
		info:   info,
	}
}

// intervalData 用于记录一个区间内的字节数
type intervalData struct {
	byteCount int
	startTime time.Time
	endTime   time.Time
}

// brutalStream 实现 analyzer.UDPStream
type brutalStream struct {
	logger       analyzer.Logger
	invalidCount int
	packetCount  int
	totalBytes   int

	score            int            // 当前得分
	intervals        []intervalData // 已结束的区间
	currentInterval  *intervalData  // 正在进行的区间
	intervalsDone    int            // 已完成的区间计数
	allIntervalsDone bool           // 是否已完成5个区间的数据收集

	blocked bool // 是否已经触发阻断

	isQuicGo bool // 是否quic-go指纹

	info analyzer.UDPInfo // 用于获取源IP
}

// 初始化统计系统
func initBrutalStats() error {
	if udpInitialized {
		return nil
	}
	udpResultMutex.Lock()
	defer udpResultMutex.Unlock()
	if udpInitialized {
		return nil
	}

	// 创建目录
	if err := os.MkdirAll(UDPBasePath, 0755); err != nil {
		return err
	}

	udpResults = &BrutalResults{
		IPList: make([]UDPIPStats, 0),
	}
	udpBlockedIPs = make(map[string]struct{})

	// 加载结果
	resultPath := filepath.Join(UDPBasePath, UDPResultFile)
	if data, err := os.ReadFile(resultPath); err == nil {
		_ = json.Unmarshal(data, &udpResults.IPList)
	}

	// 加载阻断
	blockPath := filepath.Join(UDPBasePath, UDPBlockFile)
	if data, err := os.ReadFile(blockPath); err == nil {
		var blockedList []string
		_ = json.Unmarshal(data, &blockedList)
		for _, ip := range blockedList {
			udpBlockedIPs[ip] = struct{}{}
		}
	}

	udpInitialized = true
	return nil
}

// 更新IP统计
func updateUDPIPStats(ip string, isPositive bool) error {
	if err := initBrutalStats(); err != nil {
		return err
	}

	udpResults.mu.Lock()
	defer udpResults.mu.Unlock()

	if _, blocked := udpBlockedIPs[ip]; blocked {
		return nil
	}

	now := time.Now()
	var found bool

	for i := range udpResults.IPList {
		if udpResults.IPList[i].IP == ip {
			if isPositive {
				udpResults.IPList[i].Score += positiveScoreIncrement
			} else {
				udpResults.IPList[i].Score = max(0, udpResults.IPList[i].Score-negativeScoreDecrement)
			}
			udpResults.IPList[i].LastSeen = now
			found = true
			if udpResults.IPList[i].Score >= blockThreshold {
				_ = addUDPToBlockList(ip)
			}
			break
		}
	}

	if !found && isPositive {
		udpResults.IPList = append(udpResults.IPList, UDPIPStats{
			IP:        ip,
			Score:     positiveScoreIncrement,
			FirstSeen: now,
			LastSeen:  now,
		})
	}

	return saveUDPResults()
}

// 添加到阻断名单
func addUDPToBlockList(ip string) error {
	udpBlockedIPs[ip] = struct{}{}

	blockPath := filepath.Join(UDPBasePath, UDPBlockFile)
	var blockedList []string

	if data, err := os.ReadFile(blockPath); err == nil {
		_ = json.Unmarshal(data, &blockedList)
	}

	if !contains(blockedList, ip) {
		blockedList = append(blockedList, ip)
	}

	data, err := json.MarshalIndent(blockedList, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(blockPath, data, 0644)
}

// 保存统计结果
func saveUDPResults() error {
	data, err := json.MarshalIndent(udpResults.IPList, "", "  ")
	if err != nil {
		return err
	}

	resultPath := filepath.Join(UDPBasePath, UDPResultFile)
	return os.WriteFile(resultPath, data, 0644)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Feed 每次接收 UDP 包时调用
func (s *brutalStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	srcIP := s.info.SrcIP.String()

	// 检查阻断名单
	if err := initBrutalStats(); err == nil {
		udpResultMutex.RLock()
		_, blocked := udpBlockedIPs[srcIP]
		udpResultMutex.RUnlock()
		if blocked {
			return &analyzer.PropUpdate{
				Type: analyzer.PropUpdateReplace,
				M: analyzer.PropMap{
					"blocked": true,
					"reason":  "brutal-threshold-exceed",
					"score":   s.score,
				},
			}, true
		}
	}

	// 先做基础统计
	s.packetCount++
	s.totalBytes += len(data)

	// 更新当前区间的字节数
	s.updateIntervalStats(len(data))

	// 处理区间 (收集5个区间的数据)
	now := time.Now()
	s.handleIntervals(now)

	// 如果已经被阻断，直接返回
	if s.blocked {
		_ = updateUDPIPStats(srcIP, true)
		return &analyzer.PropUpdate{
			Type: analyzer.PropUpdateReplace,
			M: analyzer.PropMap{
				"blocked": true,
				"reason":  "brutal-threshold-exceed",
				"score":   s.score,
			},
		}, true
	}

	// 首先检测流量是否为QUIC流量
	if !s.isQUIC(data) {
		_ = updateUDPIPStats(srcIP, false)
		return nil, false
	}

	// 服务器方向的流量
	if rev {
		s.invalidCount++
		if s.invalidCount >= brutalInvalidCountThreshold {
			_ = updateUDPIPStats(srcIP, false)
			return nil, true
		}
		return nil, false
	}

	// 尝试解析 QUIC ClientHello
	const minDataSize = 41
	pl, err := quic.ReadCryptoPayload(data)
	if err != nil || len(pl) < 4 {
		s.invalidCount++
		if s.invalidCount >= brutalInvalidCountThreshold {
			_ = updateUDPIPStats(srcIP, false)
		}
		return nil, s.invalidCount >= brutalInvalidCountThreshold
	}
	if pl[0] != internal.TypeClientHello {
		s.invalidCount++
		if s.invalidCount >= brutalInvalidCountThreshold {
			_ = updateUDPIPStats(srcIP, false)
		}
		return nil, s.invalidCount >= brutalInvalidCountThreshold
	}

	chLen := int(pl[1])<<16 | int(pl[2])<<8 | int(pl[3])
	if chLen < minDataSize {
		s.invalidCount++
		if s.invalidCount >= brutalInvalidCountThreshold {
			_ = updateUDPIPStats(srcIP, false)
		}
		return nil, s.invalidCount >= brutalInvalidCountThreshold
	}

	m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4:]})
	if m == nil {
		s.invalidCount++
		if s.invalidCount >= brutalInvalidCountThreshold {
			_ = updateUDPIPStats(srcIP, false)
		}
		return nil, s.invalidCount >= brutalInvalidCountThreshold
	}

	// 检查是否为quic-go指纹（复用hysteria2的检测函数）
	if isQuicGoFingerprintFromHysteria2(m) {
		s.isQuicGo = true
	}

	// 再次检查: 在解析后，也看看是否在这次处理里已经被 block
	if s.blocked {
		_ = updateUDPIPStats(srcIP, true)
		return &analyzer.PropUpdate{
			Type: analyzer.PropUpdateReplace,
			M: analyzer.PropMap{
				"blocked": true,
				"reason":  "brutal-threshold-exceed",
				"score":   s.score,
			},
		}, true
	}

	// 区间评估（在 handleIntervals 已经自动做了，score 会变化）
	// 若已完成评估且分数超标，立即阻断
	if s.allIntervalsDone && s.score > blockThreshold {
		s.blocked = true
		_ = updateUDPIPStats(srcIP, true)
		return &analyzer.PropUpdate{
			Type: analyzer.PropUpdateReplace,
			M: analyzer.PropMap{
				"blocked": true,
				"reason":  "brutal-threshold-exceed",
				"score":   s.score,
			},
		}, true
	}

	// 统计分数
	if s.allIntervalsDone {
		if s.score > 0 {
			_ = updateUDPIPStats(srcIP, true)
		} else {
			_ = updateUDPIPStats(srcIP, false)
		}
	}

	// 正常合并属性
	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateMerge,
		M:    analyzer.PropMap{"req": m},
	}, true
}

// 检测流量是否为 QUIC 流量
func (s *brutalStream) isQUIC(data []byte) bool {
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
	if chLen < 41 {
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

// updateIntervalStats 更新当前正在进行的区间的字节数
func (s *brutalStream) updateIntervalStats(byteCount int) {
	if s.currentInterval == nil {
		return
	}
	s.currentInterval.byteCount += byteCount
}

// handleIntervals 处理区间逻辑：随机启动区间、在区间超过10ms后结束并统计
func (s *brutalStream) handleIntervals(now time.Time) {
	if s.allIntervalsDone {
		return
	}

	// 只有quic-go指纹才进行后续区间检测与封锁
	if !s.isQuicGo {
		return
	}

	// 如果当前没有正在进行的区间，并且还没收集到5个区间
	if s.currentInterval == nil && s.intervalsDone < intervalCount {
		// 用一定概率启动新区间
		if rand.Float64() < intervalStartChance {
			s.currentInterval = &intervalData{
				startTime: now,
			}
		}
	} else if s.currentInterval != nil {
		// 如果已到达区间持续时间，则结束该区间
		if now.Sub(s.currentInterval.startTime) >= intervalDuration {
			s.currentInterval.endTime = now
			s.intervals = append(s.intervals, *s.currentInterval)
			s.currentInterval = nil
			s.intervalsDone++

			// 若已经收集满5个区间，进行评估
			if s.intervalsDone == intervalCount {
				s.allIntervalsDone = true
				s.evaluateIntervals()

				// 若评估完分数超过阈值，立刻阻断
				if s.score > blockThreshold {
					s.blocked = true
				}
			}
		}
	}
}

// evaluateIntervals 对 5 个区间进行评估并更新分数
func (s *brutalStream) evaluateIntervals() {
	if len(s.intervals) < intervalCount {
		return
	}

	// 收集每个区间的字节数
	vals := make([]float64, 0, intervalCount)
	for _, iv := range s.intervals {
		vals = append(vals, float64(iv.byteCount))
	}
	if len(vals) == 0 {
		return
	}

	// 计算 max, min, avg
	maxVal := vals[0]
	minVal := vals[0]
	sum := 0.0
	for _, v := range vals {
		if v > maxVal {
			maxVal = v
		}
		if v < minVal {
			minVal = v
		}
		sum += v
	}
	avg := sum / float64(len(vals))

	rangeVal := maxVal - minVal

	// 如果极差 < 平均数的5%，视为“阳性” => 加分
	if avg > 0 && rangeVal < avg*0.05 {
		s.score += positiveScoreIncrement
	} else {
		// 否则阴性 => 减分（分数不低于0）
		s.score -= negativeScoreDecrement
		if s.score < 0 {
			s.score = 0
		}
	}
}

// Close 在流结束时返回统计信息，如 blocked 与否、score 等
func (s *brutalStream) Close(limited bool) *analyzer.PropUpdate {
	srcIP := s.info.SrcIP.String()
	// 如果尚未标记 blocked，则再做一次终止判断
	blocked := s.blocked || (s.score > blockThreshold)
	if blocked {
		s.blocked = true
		_ = updateUDPIPStats(srcIP, true)
	} else {
		if s.score > 0 {
			_ = updateUDPIPStats(srcIP, true)
		} else {
			_ = updateUDPIPStats(srcIP, false)
		}
	}

	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M: analyzer.PropMap{
			"packetCount": s.packetCount,
			"totalBytes":  s.totalBytes,
			"score":       s.score,
			"blocked":     s.blocked,
		},
	}
}

// 复用 hysteria2.go 的 quic-go 指纹检测函数
func isQuicGoFingerprintFromHysteria2(m map[string]interface{}) bool {
	// hysteria2.go 文件定义的 isQuicGoFingerprint 函数
	// 由于在同一包下，可以直接调用
	return isQuicGoFingerprint(m)
}
