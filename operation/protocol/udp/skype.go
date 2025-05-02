package udp

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/v2TLS/XGFW/operation"
)

// ---- 增强持久化统计与阻断功能 ----
const (
	skypeResultFile     = "skype_result.json"
	skypeBlockFile      = "skype_block.json"
	skypeBasePath       = "/var/log/xgfw"
	skypePositiveScore  = 2
	skypeNegativeScore  = 1
	skypeBlockThreshold = 20
)

type SkypeIPStats struct {
	IP        string    `json:"ip"`
	Score     int       `json:"score"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type SkypeResults struct {
	IPList []SkypeIPStats `json:"ip_list"`
	mu     sync.Mutex
}

var (
	skypeResults     *SkypeResults
	skypeBlockedIPs  map[string]struct{}
	skypeResultMutex sync.RWMutex
	skypeInitialized bool
)

func initSkypeStats() error {
	if skypeInitialized {
		return nil
	}
	skypeResultMutex.Lock()
	defer skypeResultMutex.Unlock()
	if skypeInitialized {
		return nil
	}
	if err := os.MkdirAll(skypeBasePath, 0755); err != nil {
		return err
	}
	skypeResults = &SkypeResults{IPList: make([]SkypeIPStats, 0)}
	skypeBlockedIPs = make(map[string]struct{})

	resultPath := filepath.Join(skypeBasePath, skypeResultFile)
	if data, err := os.ReadFile(resultPath); err == nil {
		_ = json.Unmarshal(data, &skypeResults.IPList)
	}
	blockPath := filepath.Join(skypeBasePath, skypeBlockFile)
	if data, err := os.ReadFile(blockPath); err == nil {
		var blockedList []string
		_ = json.Unmarshal(data, &blockedList)
		for _, ip := range blockedList {
			skypeBlockedIPs[ip] = struct{}{}
		}
	}
	skypeInitialized = true
	return nil
}

func updateSkypeIPStats(ip string, isPositive bool) error {
	if err := initSkypeStats(); err != nil {
		return err
	}
	skypeResults.mu.Lock()
	defer skypeResults.mu.Unlock()

	if _, blocked := skypeBlockedIPs[ip]; blocked {
		return nil
	}
	now := time.Now()
	found := false
	for i := range skypeResults.IPList {
		if skypeResults.IPList[i].IP == ip {
			if isPositive {
				skypeResults.IPList[i].Score += skypePositiveScore
			} else {
				if skypeResults.IPList[i].Score > 0 {
					skypeResults.IPList[i].Score -= skypeNegativeScore
					if skypeResults.IPList[i].Score < 0 {
						skypeResults.IPList[i].Score = 0
					}
				}
			}
			skypeResults.IPList[i].LastSeen = now
			found = true
			if skypeResults.IPList[i].Score >= skypeBlockThreshold {
				_ = addSkypeToBlockList(ip)
			}
			break
		}
	}
	if !found && isPositive {
		skypeResults.IPList = append(skypeResults.IPList, SkypeIPStats{
			IP:        ip,
			Score:     skypePositiveScore,
			FirstSeen: now,
			LastSeen:  now,
		})
	}
	return saveSkypeResults()
}

func addSkypeToBlockList(ip string) error {
	skypeBlockedIPs[ip] = struct{}{}
	blockPath := filepath.Join(skypeBasePath, skypeBlockFile)
	var blockedList []string
	if data, err := os.ReadFile(blockPath); err == nil {
		_ = json.Unmarshal(data, &blockedList)
	}
	for _, blk := range blockedList {
		if blk == ip {
			return nil
		}
	}
	blockedList = append(blockedList, ip)
	data, err := json.MarshalIndent(blockedList, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(blockPath, data, 0644)
}

func saveSkypeResults() error {
	data, err := json.MarshalIndent(skypeResults.IPList, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(skypeBasePath, skypeResultFile), data, 0644)
}

// ---- 协议识别核心实现 ----

var _ analyzer.UDPAnalyzer = (*SkypeAnalyzer)(nil)

// SkypeAnalyzer detects Skype traffic using pattern matching and behavioral analysis.
type SkypeAnalyzer struct{}

func (a *SkypeAnalyzer) Name() string {
	return "skype"
}

func (a *SkypeAnalyzer) Limit() int {
	return 512000
}

func (a *SkypeAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	state := &ConnectionState{
		StartTime: time.Now(),
		Features:  make([]SkypePacketFeatures, 0, 1000),
		SrcPort:   uint16(info.SrcPort),
		DstPort:   uint16(info.DstPort),
		SrcIP:     info.SrcIP,
		DstIP:     info.DstIP,
	}
	det := &SkypeDetector{
		connState:       state,
		patternDB:       initializePatternDB(),
		tlsFingerprints: initializeTLSFingerprints(),
	}
	return &skypeStream{
		logger:   logger,
		detector: det,
		blocked:  false,
		info:     info,
	}
}

type skypeStream struct {
	logger   analyzer.Logger
	detector *SkypeDetector
	blocked  bool
	info     analyzer.UDPInfo
}

func (s *skypeStream) Feed(rev bool, data []byte) (*analyzer.PropUpdate, bool) {
	if len(data) == 0 {
		return nil, false
	}
	srcIP := s.info.SrcIP.String()

	// 阻断名单优先判定
	if err := initSkypeStats(); err == nil {
		skypeResultMutex.RLock()
		_, blocked := skypeBlockedIPs[srcIP]
		skypeResultMutex.RUnlock()
		if blocked || s.blocked {
			s.blocked = true
			return &analyzer.PropUpdate{
				Type: analyzer.PropUpdateReplace,
				M:    analyzer.PropMap{"blocked": true, "reason": "skype-threshold-exceed"},
			}, true
		}
	}

	features := s.detector.extractFeatures(data, rev)
	foundSkype := s.detector.deepPacketInspection(features)

	if foundSkype && !s.blocked {
		_ = updateSkypeIPStats(srcIP, true)
		if err := initSkypeStats(); err == nil {
			skypeResultMutex.RLock()
			_, blocked := skypeBlockedIPs[srcIP]
			skypeResultMutex.RUnlock()
			if blocked {
				s.blocked = true
				return &analyzer.PropUpdate{
					Type: analyzer.PropUpdateReplace,
					M:    analyzer.PropMap{"blocked": true, "reason": "skype-threshold-exceed"},
				}, true
			}
		}
		// 协议特征命中但分数未到阈值
		return &analyzer.PropUpdate{
			Type: analyzer.PropUpdateReplace,
			M: analyzer.PropMap{
				"yes":    true,
				"result": "skype",
				"blocked": false,
			},
		}, true
	} else if !foundSkype {
		_ = updateSkypeIPStats(srcIP, false)
	}
	return nil, false
}

func (s *skypeStream) Close(limited bool) *analyzer.PropUpdate {
	srcIP := s.info.SrcIP.String()
	if err := initSkypeStats(); err == nil {
		skypeResultMutex.RLock()
		blocked := false
		_, blocked = skypeBlockedIPs[srcIP]
		skypeResultMutex.RUnlock()
		if blocked || s.blocked {
			s.blocked = true
			return &analyzer.PropUpdate{
				Type: analyzer.PropUpdateReplace,
				M:    analyzer.PropMap{"blocked": true, "reason": "skype-threshold-exceed"},
			}
		}
	}
	return nil
}

type ConnectionState struct {
	SrcIP            net.IP
	DstIP            net.IP
	SrcPort          uint16
	DstPort          uint16
	StartTime        time.Time
	LastSeen         time.Time
	PacketCount      uint32
	BytesTransferred uint64
	Features         []SkypePacketFeatures
	IsBlocked        bool
	mu               sync.Mutex
}

// SkypePacketFeatures stores packet-specific features for Skype
type SkypePacketFeatures struct {
	Size        uint16
	PayloadHash [32]byte
	Timestamp   time.Time
	Direction   uint8 // 0: outbound, 1: inbound
	Protocol    uint8 // 0: TCP, 1: UDP
}

type SkypeDetector struct {
	connState       *ConnectionState
	patternDB       map[string][]byte
	tlsFingerprints map[string]bool
}

func initializePatternDB() map[string][]byte {
	return map[string][]byte{
		"header_pattern": {0x02, 0x01, 0x47, 0x49},
		"keepalive":      {0x02, 0x00},
		"audio_pattern":  {0x02, 0x0D},
		"video_pattern":  {0x02, 0x0E},
	}
}

func initializeTLSFingerprints() map[string]bool {
	return map[string]bool{
		"1603010200010001fc0303": true,
		"1603010200010001fc0304": true,
	}
}

func (sd *SkypeDetector) extractFeatures(data []byte, rev bool) *SkypePacketFeatures {
	f := &SkypePacketFeatures{
		Size:      uint16(len(data)),
		Timestamp: time.Now(),
		Protocol:  1, // UDP
	}
	if rev {
		f.Direction = 1 // inbound
	}
	if len(data) > 0 {
		f.PayloadHash = sha256.Sum256(data)
	}
	return f
}

func (sd *SkypeDetector) deepPacketInspection(features *SkypePacketFeatures) bool {
	sd.connState.mu.Lock()
	defer sd.connState.mu.Unlock()

	sd.connState.PacketCount++
	sd.connState.BytesTransferred += uint64(features.Size)
	sd.connState.Features = append(sd.connState.Features, *features)
	sd.connState.LastSeen = features.Timestamp

	return sd.analyzeFeatures()
}

func (sd *SkypeDetector) analyzeFeatures() bool {
	if len(sd.connState.Features) < 10 {
		return false
	}

	var smallPackets, mediumPackets, largePackets int
	for _, f := range sd.connState.Features {
		switch {
		case f.Size < 100:
			smallPackets++
		case f.Size < 500:
			mediumPackets++
		default:
			largePackets++
		}
	}

	patterns := sd.analyzeTrafficPatterns()
	if !patterns {
		return false
	}

	intervals := sd.analyzeTimeIntervals()
	if !intervals {
		return false
	}

	payloadMatch := sd.analyzePayloadPatterns()
	if !payloadMatch {
		return false
	}

	skypeScore := 0
	if float64(smallPackets)/float64(len(sd.connState.Features)) > 0.6 {
		skypeScore += 2
	}
	if sd.connState.PacketCount > 20 && sd.connState.BytesTransferred > 1000 {
		skypeScore += 2
	}
	if patterns {
		skypeScore += 3
	}
	if intervals {
		skypeScore += 2
	}
	if payloadMatch {
		skypeScore += 3
	}

	return skypeScore >= 8
}

func (sd *SkypeDetector) analyzeTrafficPatterns() bool {
	if len(sd.connState.Features) < 10 {
		return false
	}

	var pattern uint16
	startIdx := len(sd.connState.Features) - 10
	for i := startIdx; i < len(sd.connState.Features); i++ {
		pattern = (pattern << 1) | uint16(sd.connState.Features[i].Direction)
	}

	return pattern&0x0F0F == 0x0505 || pattern&0x0F0F == 0x0A0A
}

func (sd *SkypeDetector) analyzeTimeIntervals() bool {
	if len(sd.connState.Features) < 3 {
		return false
	}

	var intervals []time.Duration
	for i := 1; i < len(sd.connState.Features); i++ {
		interval := sd.connState.Features[i].Timestamp.Sub(sd.connState.Features[i-1].Timestamp)
		intervals = append(intervals, interval)
	}

	var heartbeatCount int
	for _, interval := range intervals {
		if interval >= 20*time.Millisecond && interval <= 30*time.Millisecond {
			heartbeatCount++
		}
	}
	return heartbeatCount >= len(intervals)/3
}

func (sd *SkypeDetector) analyzePayloadPatterns() bool {
	var matches int
	for _, feature := range sd.connState.Features {
		for _, pattern := range sd.patternDB {
			if bytes.Contains(feature.PayloadHash[:], pattern) {
				matches++
				break
			}
		}
	}
	return matches >= 3
}

func (sd *SkypeDetector) blockConnection() error {
	sd.connState.mu.Lock()
	defer sd.connState.mu.Unlock()

	if sd.connState.IsBlocked {
		return nil
	}

	rules := []string{
		fmt.Sprintf("-A INPUT -s %s -j DROP", sd.connState.SrcIP),
		fmt.Sprintf("-A OUTPUT -d %s -j DROP", sd.connState.DstIP),
	}

	for _, rule := range rules {
		cmd := fmt.Sprintf("iptables %s", rule)
		log.Printf("Applying blocking rule: %s", cmd)
	}

	sd.connState.IsBlocked = true
	return nil
}
