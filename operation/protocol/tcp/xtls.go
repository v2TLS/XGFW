// Only avaliable for XTLS/Go, not for XTLS Vision.

package tcp

import (
    "encoding/binary"
    "fmt"
    "os"
    "path/filepath"
    "sync"
    "time"

    "github.com/v2TLS/XGFW/operation/protocol"
)

var _ analyzer.TCPAnalyzer = (*XTLSAnalyzer)(nil)

// 固定配置
const (
    ResultFile = "xtls_result.json"
    BlockFile  = "xtls_block.json"
    BasePath   = "/var/log/xgfw"
)

// XTLSStats 记录单个IP的统计信息
type XTLSStats struct {
    IP        string    `json:"ip"`
    Hits      int       `json:"hits"`
    FirstSeen time.Time `json:"first_seen"`
    LastSeen  time.Time `json:"last_seen"`
    Reason    string    `json:"reason"`
}

type XTLSResults struct {
    IPList []XTLSStats `json:"ip_list"`
    mu     sync.Mutex
}

var (
    results     *XTLSResults
    blockedIPs  map[string]struct{}
    resultMutex sync.RWMutex
    initialized bool
)

// XTLSAnalyzer 实现 analyzer.TCPAnalyzer
type XTLSAnalyzer struct{}

func (a *XTLSAnalyzer) Name() string {
    return "xtls"
}

func (a *XTLSAnalyzer) Limit() int {
    return 1024 // 只需部分数据即可检测
}

// 初始化统计系统
func initXTLSStats() error {
    if initialized {
        return nil
    }
    resultMutex.Lock()
    defer resultMutex.Unlock()
    if initialized {
        return nil
    }
    if err := os.MkdirAll(BasePath, 0755); err != nil {
        return fmt.Errorf("failed to create base directory: %w", err)
    }
    results = &XTLSResults{IPList: make([]XTLSStats, 0)}
    blockedIPs = make(map[string]struct{})
    // 读取历史结果
    resultPath := filepath.Join(BasePath, ResultFile)
    if data, err := os.ReadFile(resultPath); err == nil {
        _ = jsonUnmarshal(data, &results.IPList)
    }
    // 读取阻断IP
    blockPath := filepath.Join(BasePath, BlockFile)
    if data, err := os.ReadFile(blockPath); err == nil {
        var blockedList []string
        _ = jsonUnmarshal(data, &blockedList)
        for _, ip := range blockedList {
            blockedIPs[ip] = struct{}{}
        }
    }
    initialized = true
    return nil
}

// 更新IP统计
func updateXTLSStats(ip, reason string) error {
    if err := initXTLSStats(); err != nil {
        return err
    }
    results.mu.Lock()
    defer results.mu.Unlock()
    if _, blocked := blockedIPs[ip]; blocked {
        return nil
    }
    now := time.Now()
    found := false
    for i := range results.IPList {
        if results.IPList[i].IP == ip {
            results.IPList[i].Hits++
            results.IPList[i].LastSeen = now
            results.IPList[i].Reason = reason
            found = true
            if results.IPList[i].Hits >= BlockThreshold {
                if err := addToBlockList(ip); err != nil {
                    return err
                }
            }
            break
        }
    }
    if !found {
        stats := XTLSStats{
            IP:        ip,
            Hits:      1,
            FirstSeen: now,
            LastSeen:  now,
            Reason:    reason,
        }
        results.IPList = append(results.IPList, stats)
        if stats.Hits >= BlockThreshold {
            if err := addToBlockList(ip); err != nil {
                return err
            }
        }
    }
    return saveResults()
}

// 阻断IP
func addToBlockList(ip string) error {
    blockedIPs[ip] = struct{}{}
    blockPath := filepath.Join(BasePath, BlockFile)
    var blockedList []string
    if data, err := os.ReadFile(blockPath); err == nil {
        _ = jsonUnmarshal(data, &blockedList)
    }
    if !contains(blockedList, ip) {
        blockedList = append(blockedList, ip)
    }
    data, err := jsonMarshalIndent(blockedList)
    if err != nil {
        return err
    }
    return os.WriteFile(blockPath, data, 0644)
}

// 保存统计结果
func saveResults() error {
    data, err := jsonMarshalIndent(results.IPList)
    if err != nil {
        return err
    }
    resultPath := filepath.Join(BasePath, ResultFile)
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

// --- JSON helper, 支持 go1.16+ 兼容老go
func jsonUnmarshal(data []byte, v interface{}) error {
    // 兼容import
    type alias = interface{}
    return json.Unmarshal(data, v)
}
func jsonMarshalIndent(v interface{}) ([]byte, error) {
    // 兼容import
    type alias = interface{}
    return json.MarshalIndent(v, "", "  ")
}

// XTLS流分析器
type xtlsStream struct {
    logger analyzer.Logger
    info   analyzer.TCPInfo
    done   bool
}

// NewTCP 实现
func (a *XTLSAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    return &xtlsStream{
        logger: logger,
        info:   info,
    }
}

// Feed 实现检测逻辑
func (s *xtlsStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
    if skip != 0 || len(data) == 0 || s.done {
        return nil, true
    }
    ip := s.info.DstIP.String()
    // 检查变长alert/close_notify
    if reason := detectXTLSAlert(data); reason != "" {
        _ = updateXTLSStats(ip, reason)
        s.logger.Infof("XTLS blocked: %s for %s", reason, ip)
        s.done = true
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "block":   true,
                "protocol": "xtls",
                "reason":  reason,
            },
        }, true
    }
    // 检查TLS 1.2 nonce明文序列号
    if detectTLS12NonceSeq(data) {
        _ = updateXTLSStats(ip, "tls12_nonce_sequence")
        s.logger.Infof("XTLS blocked: tls12_nonce_sequence for %s", ip)
        s.done = true
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "block":   true,
                "protocol": "xtls",
                "reason":  "tls12_nonce_sequence",
            },
        }, true
    }
    return nil, false
}

func (s *xtlsStream) Close(limited bool) *analyzer.PropUpdate {
    return nil
}

// 检查变长alert/close_notify
func detectXTLSAlert(data []byte) string {
    // TLS record header: ContentType(1) + Version(2) + Length(2)
    // ContentType = 21(alert), Version=3.3/3.4, Length=变长
    for i := 0; i+5 <= len(data); i++ {
        if data[i] == 21 && data[i+1] == 3 && (data[i+2] == 3 || data[i+2] == 4) {
            length := int(binary.BigEndian.Uint16(data[i+3 : i+5]))
            // 只要不是典型26（即总长31）就判定
            if length != 26 {
                return "forbidden_alert"
            }
        }
    }
    return ""
}

// 检查TLS 1.2 AEAD明文nonce序列号
func detectTLS12NonceSeq(data []byte) bool {
    // ContentType(23) + Version(3,3) + Length(2) + 序列号(8)...
    for i := 0; i+13 <= len(data); i++ {
        if data[i] == 23 && data[i+1] == 3 && data[i+2] == 3 {
            seq := binary.BigEndian.Uint64(data[i+5 : i+13])
            // 仅作存在性检测（递增特征可更复杂）
            if seq != 0 {
                return true
            }
        }
    }
    return false
}
