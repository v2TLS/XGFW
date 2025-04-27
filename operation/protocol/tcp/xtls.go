package tcp

import (
    "encoding/binary"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "sync"
    "time"

    "github.com/v2TLS/XGFW/operation"
)

var _ analyzer.TCPAnalyzer = (*XTLSAnalyzer)(nil)

const (
    xtlsResultFile = "xtls_result.json"
    xtlsBlockFile  = "xtls_block.json"
    xtlsBasePath   = "/var/log/xgfw"
    xtlsBlockThreshold = 1
)

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
    xtlsResults     *XTLSResults
    xtlsBlockedIPs  map[string]struct{}
    xtlsResultMutex sync.RWMutex
    xtlsInitialized bool
)

type XTLSAnalyzer struct{}

func (a *XTLSAnalyzer) Name() string {
    return "xtls"
}

func (a *XTLSAnalyzer) Limit() int {
    return 1024
}

func xtlsInitStats() error {
    if xtlsInitialized {
        return nil
    }
    xtlsResultMutex.Lock()
    defer xtlsResultMutex.Unlock()
    if xtlsInitialized {
        return nil
    }
    if err := os.MkdirAll(xtlsBasePath, 0755); err != nil {
        return fmt.Errorf("failed to create base directory: %w", err)
    }
    xtlsResults = &XTLSResults{IPList: make([]XTLSStats, 0)}
    xtlsBlockedIPs = make(map[string]struct{})
    resultPath := filepath.Join(xtlsBasePath, xtlsResultFile)
    if data, err := os.ReadFile(resultPath); err == nil {
        _ = json.Unmarshal(data, &xtlsResults.IPList)
    }
    blockPath := filepath.Join(xtlsBasePath, xtlsBlockFile)
    if data, err := os.ReadFile(blockPath); err == nil {
        var blockedList []string
        _ = json.Unmarshal(data, &blockedList)
        for _, ip := range blockedList {
            xtlsBlockedIPs[ip] = struct{}{}
        }
    }
    xtlsInitialized = true
    return nil
}

func xtlsUpdateStats(ip, reason string) error {
    if err := xtlsInitStats(); err != nil {
        return err
    }
    xtlsResults.mu.Lock()
    defer xtlsResults.mu.Unlock()
    if _, blocked := xtlsBlockedIPs[ip]; blocked {
        return nil
    }
    now := time.Now()
    found := false
    for i := range xtlsResults.IPList {
        if xtlsResults.IPList[i].IP == ip {
            xtlsResults.IPList[i].Hits++
            xtlsResults.IPList[i].LastSeen = now
            xtlsResults.IPList[i].Reason = reason
            found = true
            if xtlsResults.IPList[i].Hits >= xtlsBlockThreshold {
                if err := xtlsAddToBlockList(ip); err != nil {
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
        xtlsResults.IPList = append(xtlsResults.IPList, stats)
        if stats.Hits >= xtlsBlockThreshold {
            if err := xtlsAddToBlockList(ip); err != nil {
                return err
            }
        }
    }
    return xtlsSaveResults()
}

func xtlsAddToBlockList(ip string) error {
    xtlsBlockedIPs[ip] = struct{}{}
    blockPath := filepath.Join(xtlsBasePath, xtlsBlockFile)
    var blockedList []string
    if data, err := os.ReadFile(blockPath); err == nil {
        _ = json.Unmarshal(data, &blockedList)
    }
    if !xtlsContains(blockedList, ip) {
        blockedList = append(blockedList, ip)
    }
    data, err := json.MarshalIndent(blockedList, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(blockPath, data, 0644)
}

func xtlsSaveResults() error {
    data, err := json.MarshalIndent(xtlsResults.IPList, "", "  ")
    if err != nil {
        return err
    }
    resultPath := filepath.Join(xtlsBasePath, xtlsResultFile)
    return os.WriteFile(resultPath, data, 0644)
}

func xtlsContains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}

type xtlsStream struct {
    logger analyzer.Logger
    info   analyzer.TCPInfo
    done   bool
}

func (a *XTLSAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    return &xtlsStream{
        logger: logger,
        info:   info,
    }
}

func (s *xtlsStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
    if skip != 0 || len(data) == 0 || s.done {
        return nil, true
    }
    ip := s.info.DstIP.String()
    if reason := detectXTLSAlert(data); reason != "" {
        _ = xtlsUpdateStats(ip, reason)
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
    if detectTLS12NonceSeq(data) {
        _ = xtlsUpdateStats(ip, "tls12_nonce_sequence")
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

func detectXTLSAlert(data []byte) string {
    for i := 0; i+5 <= len(data); i++ {
        if data[i] == 21 && data[i+1] == 3 && (data[i+2] == 3 || data[i+2] == 4) {
            length := int(binary.BigEndian.Uint16(data[i+3 : i+5]))
            if length != 26 {
                return "forbidden_alert"
            }
        }
    }
    return ""
}

func detectTLS12NonceSeq(data []byte) bool {
    for i := 0; i+13 <= len(data); i++ {
        if data[i] == 23 && data[i+1] == 3 && data[i+2] == 3 {
            seq := binary.BigEndian.Uint64(data[i+5 : i+13])
            if seq != 0 {
                return true
            }
        }
    }
    return false
}
