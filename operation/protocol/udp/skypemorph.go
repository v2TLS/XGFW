package udp

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/v2TLS/XGFW/operation"
)

const (
	skypemorphResultFile     = "skypemorph_result.json"
	skypemorphBlockFile      = "skypemorph_block.json"
	skypemorphBasePath       = "/var/log/xgfw"
	skypemorphPositiveScore  = 2
	skypemorphNegativeScore  = 1
	skypemorphBlockThreshold = 20
)

type SkypemorphIPStats struct {
	IP        string    `json:"ip"`
	Score     int       `json:"score"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type SkypemorphResults struct {
	IPList []SkypemorphIPStats `json:"ip_list"`
	mu     sync.Mutex
}

var (
	skypemorphResults     *SkypemorphResults
	skypemorphBlockedIPs  map[string]struct{}
	skypemorphResultMutex sync.RWMutex
	skypemorphInitialized bool
)

func initSkypemorphStats() error {
	if skypemorphInitialized {
		return nil
	}
	skypemorphResultMutex.Lock()
	defer skypemorphResultMutex.Unlock()
	if skypemorphInitialized {
		return nil
	}
	if err := os.MkdirAll(skypemorphBasePath, 0755); err != nil {
		return err
	}
	skypemorphResults = &SkypemorphResults{IPList: make([]SkypemorphIPStats, 0)}
	skypemorphBlockedIPs = make(map[string]struct{})

	resultPath := filepath.Join(skypemorphBasePath, skypemorphResultFile)
	if data, err := os.ReadFile(resultPath); err == nil {
		_ = json.Unmarshal(data, &skypemorphResults.IPList)
	}
	blockPath := filepath.Join(skypemorphBasePath, skypemorphBlockFile)
	if data, err := os.ReadFile(blockPath); err == nil {
		var blockedList []string
		_ = json.Unmarshal(data, &blockedList)
		for _, ip := range blockedList {
			skypemorphBlockedIPs[ip] = struct{}{}
		}
	}
	skypemorphInitialized = true
	return nil
}

func updateSkypemorphIPStats(ip string, isPositive bool) error {
	if err := initSkypemorphStats(); err != nil {
		return err
	}
	skypemorphResults.mu.Lock()
	defer skypemorphResults.mu.Unlock()

	if _, blocked := skypemorphBlockedIPs[ip]; blocked {
		return nil
	}
	now := time.Now()
	found := false
	for i := range skypemorphResults.IPList {
		if skypemorphResults.IPList[i].IP == ip {
			if isPositive {
				skypemorphResults.IPList[i].Score += skypemorphPositiveScore
			} else {
				if skypemorphResults.IPList[i].Score > 0 {
					skypemorphResults.IPList[i].Score -= skypemorphNegativeScore
					if skypemorphResults.IPList[i].Score < 0 {
						skypemorphResults.IPList[i].Score = 0
					}
				}
			}
			skypemorphResults.IPList[i].LastSeen = now
			found = true
			if skypemorphResults.IPList[i].Score >= skypemorphBlockThreshold {
				_ = addSkypemorphToBlockList(ip)
			}
			break
		}
	}
	if !found && isPositive {
		skypemorphResults.IPList = append(skypemorphResults.IPList, SkypemorphIPStats{
			IP:        ip,
			Score:     skypemorphPositiveScore,
			FirstSeen: now,
			LastSeen:  now,
		})
	}
	return saveSkypemorphResults()
}

func addSkypemorphToBlockList(ip string) error {
	skypemorphBlockedIPs[ip] = struct{}{}
	blockPath := filepath.Join(skypemorphBasePath, skypemorphBlockFile)
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

func saveSkypemorphResults() error {
	data, err := json.MarshalIndent(skypemorphResults.IPList, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(skypemorphBasePath, skypemorphResultFile), data, 0644)
}

// ---- 协议检测实现 ----

var _ analyzer.UDPAnalyzer = (*SkypeMorphAnalyzer)(nil)

// SkypeMorphAnalyzer uses heuristics to detect SkypeMorph traffic based on
// its imitation of Skype protocols. The heuristics are based on known discrepancies
// in SkypeMorph's imitation of Skype traffic.
type SkypeMorphAnalyzer struct{}

func (a *SkypeMorphAnalyzer) Name() string {
	return "skypemorph"
}

func (a *SkypeMorphAnalyzer) Limit() int {
	return 512000
}

func (a *SkypeMorphAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return newSkypeMorphStream(logger, info)
}

type skypeMorphStream struct {
	logger   analyzer.Logger
	first    bool
	seq      [4]int
	seqIndex int
	features []PacketFeatures
	info     analyzer.UDPInfo
	blocked  bool
}

// PacketFeatures stores packet-specific features
type PacketFeatures struct {
	Size        uint16
	PayloadHash [32]byte
	Timestamp   time.Time
	Direction   uint8 // 0: outbound, 1: inbound
}

func newSkypeMorphStream(logger analyzer.Logger, info analyzer.UDPInfo) *skypeMorphStream {
	return &skypeMorphStream{
		logger:   logger,
		features: make([]PacketFeatures, 0, 1000),
		first:    true,
		info:     info,
	}
}

func (s *skypeMorphStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	if len(data) == 0 {
		return nil, false
	}
	srcIP := s.info.SrcIP.String()

	// 阻断名单优先判定
	if err := initSkypemorphStats(); err == nil {
		skypemorphResultMutex.RLock()
		_, blocked := skypemorphBlockedIPs[srcIP]
		skypemorphResultMutex.RUnlock()
		if blocked || s.blocked {
			s.blocked = true
			return &analyzer.PropUpdate{
				Type: analyzer.PropUpdateReplace,
				M:    analyzer.PropMap{"blocked": true, "reason": "skypemorph-threshold-exceed"},
			}, true
		}
	}

	// Extract features
	feature := PacketFeatures{
		Size:      uint16(len(data)),
		Timestamp: time.Now(),
	}
	if rev {
		feature.Direction = 1
	}
	if len(data) > 0 {
		feature.PayloadHash = sha256.Sum256(data)
	}

	// Update state
	s.features = append(s.features, feature)
	s.seq[s.seqIndex] += len(data)

	// 检测逻辑
	positive := false
	if s.shouldAnalyze() {
		positive = s.analyzeTraffic()
	}

	if positive {
		_ = updateSkypemorphIPStats(srcIP, true)
		if err := initSkypemorphStats(); err == nil {
			skypemorphResultMutex.RLock()
			_, blocked := skypemorphBlockedIPs[srcIP]
			skypemorphResultMutex.RUnlock()
			if blocked {
				s.blocked = true
				return &analyzer.PropUpdate{
					Type: analyzer.PropUpdateReplace,
					M:    analyzer.PropMap{"blocked": true, "reason": "skypemorph-threshold-exceed"},
				}, true
			}
		}
		log.Printf("INFO: Detected SkypeMorph traffic")
		return &analyzer.PropUpdate{
			Type: analyzer.PropUpdateReplace,
			M: analyzer.PropMap{
				"yes":     true,
				"result":  "skypemorph",
				"blocked": false,
			},
		}, true
	} else {
		_ = updateSkypemorphIPStats(srcIP, false)
	}

	return nil, false
}

func (s *skypeMorphStream) Close(limited bool) *analyzer.PropUpdate {
	srcIP := s.info.SrcIP.String()
	if err := initSkypemorphStats(); err == nil {
		skypemorphResultMutex.RLock()
		blocked := false
		_, blocked = skypemorphBlockedIPs[srcIP]
		skypemorphResultMutex.RUnlock()
		if blocked || s.blocked {
			s.blocked = true
			return &analyzer.PropUpdate{
				Type: analyzer.PropUpdateReplace,
				M:    analyzer.PropMap{"blocked": true, "reason": "skypemorph-threshold-exceed"},
			}
		}
	}
	return nil
}

func (s *skypeMorphStream) shouldAnalyze() bool {
	return len(s.features) >= 10 && s.seqIndex >= 3
}

func (s *skypeMorphStream) analyzeTraffic() bool {
	// 1. Check for typical SkypeMorph packet pattern
	if s.seq[0] <= 100 && s.seq[1] <= 500 && s.seq[2] <= 1000 && s.seq[3] <= 1500 {
		return true
	}
	// 2. Check for SkypeMorph-specific payload patterns
	for _, f := range s.features {
		if bytes.Contains(f.PayloadHash[:], []byte{0x02, 0x01, 0x47, 0x49}) {
			return true
		}
	}
	// 3. Check for periodic message patterns
	var intervals []time.Duration
	for i := 1; i < len(s.features); i++ {
		interval := s.features[i].Timestamp.Sub(s.features[i-1].Timestamp)
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
