package tcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/v2TLS/XGFW/operation"
)

var _ analyzer.TCPAnalyzer = (*FETAnalyzer)(nil)

// FETAnalyzer stands for "Fully Encrypted Traffic" analyzer.
// It implements an algorithm to detect fully encrypted proxy protocols
// such as Shadowsocks, mentioned in the following paper:
// https://gfw.report/publications/usenixsecurity23/data/paper/paper.pdf
type FETAnalyzer struct{}

func (a *FETAnalyzer) Name() string {
	return "fet"
}

func (a *FETAnalyzer) Limit() int {
	// We only really look at the first packet
	return 8192
}

func (a *FETAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	return newFETStream(logger, info)
}

// ==== 增强功能持久化部分 ====

// 唯一变量名前缀（fet）防止和同目录其它实现冲突
const (
	fetResultFile     = "fet_result.json"
	fetBlockFile      = "fet_block.json"
	fetBasePath       = "/var/log/xgfw"
	fetPositiveScore  = 2
	fetNegativeScore  = 1
	fetBlockThreshold = 20
)

// FETIPStats 记录单个IP的统计信息
type FETIPStats struct {
	IP        string    `json:"ip"`
	Score     int       `json:"score"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// FETResults 记录所有IP统计信息
type FETResults struct {
	IPList []FETIPStats `json:"ip_list"`
	mu     sync.Mutex
}

// 全局变量
var (
	fetResults     *FETResults
	fetBlockedIPs  map[string]struct{}
	fetResultMutex sync.RWMutex
	fetInitialized bool
)

// 初始化统计系统
func initFETStats() error {
	if fetInitialized {
		return nil
	}
	fetResultMutex.Lock()
	defer fetResultMutex.Unlock()
	if fetInitialized {
		return nil
	}
	if err := os.MkdirAll(fetBasePath, 0755); err != nil {
		return err
	}
	fetResults = &FETResults{IPList: make([]FETIPStats, 0)}
	fetBlockedIPs = make(map[string]struct{})

	resultPath := filepath.Join(fetBasePath, fetResultFile)
	if data, err := os.ReadFile(resultPath); err == nil {
		_ = json.Unmarshal(data, &fetResults.IPList)
	}
	blockPath := filepath.Join(fetBasePath, fetBlockFile)
	if data, err := os.ReadFile(blockPath); err == nil {
		var blockedList []string
		_ = json.Unmarshal(data, &blockedList)
		for _, ip := range blockedList {
			fetBlockedIPs[ip] = struct{}{}
		}
	}
	fetInitialized = true
	return nil
}

// 更新IP统计
func updateFETIPStats(ip string, isPositive bool) error {
	if err := initFETStats(); err != nil {
		return err
	}
	fetResults.mu.Lock()
	defer fetResults.mu.Unlock()

	if _, blocked := fetBlockedIPs[ip]; blocked {
		return nil
	}
	now := time.Now()
	found := false
	for i := range fetResults.IPList {
		if fetResults.IPList[i].IP == ip {
			if isPositive {
				fetResults.IPList[i].Score += fetPositiveScore
			} else {
				if fetResults.IPList[i].Score > 0 {
					fetResults.IPList[i].Score -= fetNegativeScore
					if fetResults.IPList[i].Score < 0 {
						fetResults.IPList[i].Score = 0
					}
				}
			}
			fetResults.IPList[i].LastSeen = now
			found = true
			if fetResults.IPList[i].Score >= fetBlockThreshold {
				_ = addFETToBlockList(ip)
			}
			break
		}
	}
	if !found && isPositive {
		fetResults.IPList = append(fetResults.IPList, FETIPStats{
			IP:        ip,
			Score:     fetPositiveScore,
			FirstSeen: now,
			LastSeen:  now,
		})
	}
	return saveFETResults()
}

// 添加IP到阻断名单
func addFETToBlockList(ip string) error {
	fetBlockedIPs[ip] = struct{}{}
	blockPath := filepath.Join(fetBasePath, fetBlockFile)
	var blockedList []string
	if data, err := os.ReadFile(blockPath); err == nil {
		_ = json.Unmarshal(data, &blockedList)
	}
	// 去重
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

// 保存统计结果
func saveFETResults() error {
	data, err := json.MarshalIndent(fetResults.IPList, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(fetBasePath, fetResultFile), data, 0644)
}

// ========== 检测核心及增强入口 ==========

type fetStream struct {
	logger analyzer.Logger
	info   analyzer.TCPInfo
}

func newFETStream(logger analyzer.Logger, info analyzer.TCPInfo) *fetStream {
	return &fetStream{logger: logger, info: info}
}

func (s *fetStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
	if skip != 0 {
		return nil, true
	}
	if len(data) == 0 {
		return nil, false
	}

	ip := s.info.SrcIP.String()
	// 检查阻断名单
	if err := initFETStats(); err == nil {
		fetResultMutex.RLock()
		_, blocked := fetBlockedIPs[ip]
		fetResultMutex.RUnlock()
		if blocked {
			return &analyzer.PropUpdate{
				Type: analyzer.PropUpdateReplace,
				M: analyzer.PropMap{
					"blocked": true,
					"reason":  "fet-threshold-exceed",
				},
			}, true
		}
	}

	ex1 := averagePopCount(data)
	ex2 := isFirstSixPrintable(data)
	ex3 := printablePercentage(data)
	ex4 := contiguousPrintable(data)
	ex5 := isTLSorHTTP(data)
	exempt := (ex1 <= 3.4 || ex1 >= 4.6) || ex2 || ex3 > 0.5 || ex4 > 20 || ex5
	positive := !exempt

	if positive {
		_ = updateFETIPStats(ip, true)
		if err := initFETStats(); err == nil {
			fetResultMutex.RLock()
			_, blocked := fetBlockedIPs[ip]
			fetResultMutex.RUnlock()
			if blocked {
				return &analyzer.PropUpdate{
					Type: analyzer.PropUpdateReplace,
					M: analyzer.PropMap{
						"blocked": true,
						"reason":  "fet-threshold-exceed",
					},
				}, true
			}
		}
	} else {
		_ = updateFETIPStats(ip, false)
	}

	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M: analyzer.PropMap{
			"ex1":     ex1,
			"ex2":     ex2,
			"ex3":     ex3,
			"ex4":     ex4,
			"ex5":     ex5,
			"yes":     positive,
			"blocked": false,
		},
	}, true
}

func (s *fetStream) Close(limited bool) *analyzer.PropUpdate {
	ip := s.info.SrcIP.String()
	// 在Close时也再次写入分数（便于最终block及时）
	if err := initFETStats(); err == nil {
		fetResultMutex.RLock()
		blocked := false
		_, blocked = fetBlockedIPs[ip]
		fetResultMutex.RUnlock()
		if blocked {
			return &analyzer.PropUpdate{
				Type: analyzer.PropUpdateReplace,
				M: analyzer.PropMap{
					"blocked": true,
					"reason":  "fet-threshold-exceed",
				},
			}
		}
	}
	return nil
}

func popCount(b byte) int {
	count := 0
	for b != 0 {
		count += int(b & 1)
		b >>= 1
	}
	return count
}

// averagePopCount returns the average popcount of the given bytes.
// This is the "Ex1" metric in the paper.
func averagePopCount(bytes []byte) float32 {
	if len(bytes) == 0 {
		return 0
	}
	total := 0
	for _, b := range bytes {
		total += popCount(b)
	}
	return float32(total) / float32(len(bytes))
}

// isFirstSixPrintable returns true if the first six bytes are printable ASCII.
// This is the "Ex2" metric in the paper.
func isFirstSixPrintable(bytes []byte) bool {
	if len(bytes) < 6 {
		return false
	}
	for i := range bytes[:6] {
		if !isPrintable(bytes[i]) {
			return false
		}
	}
	return true
}

// printablePercentage returns the percentage of printable ASCII bytes.
// This is the "Ex3" metric in the paper.
func printablePercentage(bytes []byte) float32 {
	if len(bytes) == 0 {
		return 0
	}
	count := 0
	for i := range bytes {
		if isPrintable(bytes[i]) {
			count++
		}
	}
	return float32(count) / float32(len(bytes))
}

// contiguousPrintable returns the length of the longest contiguous sequence of
// printable ASCII bytes.
// This is the "Ex4" metric in the paper.
func contiguousPrintable(bytes []byte) int {
	if len(bytes) == 0 {
		return 0
	}
	maxCount := 0
	current := 0
	for i := range bytes {
		if isPrintable(bytes[i]) {
			current++
		} else {
			if current > maxCount {
				maxCount = current
			}
			current = 0
		}
	}
	if current > maxCount {
		maxCount = current
	}
	return maxCount
}

// isTLSorHTTP returns true if the given bytes look like TLS or HTTP.
// This is the "Ex5" metric in the paper.
func isTLSorHTTP(bytes []byte) bool {
	if len(bytes) < 3 {
		return false
	}
	// "We observe that the GFW exempts any connection whose first
	// three bytes match the following regular expression:
	// [\x16-\x17]\x03[\x00-\x09]" - from the paper in Section 4.3
	if bytes[0] >= 0x16 && bytes[0] <= 0x17 &&
		bytes[1] == 0x03 && bytes[2] <= 0x09 {
		return true
	}
	// HTTP request
	str := string(bytes[:3])
	return str == "GET" || str == "HEA" || str == "POS" ||
		str == "PUT" || str == "DEL" || str == "CON" ||
		str == "OPT" || str == "TRA" || str == "PAT"
}

func isPrintable(b byte) bool {
	return b >= 0x20 && b <= 0x7e
}
