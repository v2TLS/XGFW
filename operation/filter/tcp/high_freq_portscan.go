package tcp

import (
    "net"
    "sync"
    "time"

    filter "github.com/v2TLS/XGFW/operation"
)

// 全局IP端口扫描状态表：srcIP -> map[dstPort]lastSeen
var (
    hfpsTable     = make(map[string]map[uint16]time.Time)
    hfpsTableLock sync.Mutex
    hfpsTimeWindow     = 5 * time.Second         // 端口扫描时间窗口
    hfpsPortThreshold  = 10                      // 单窗口内尝试端口数阈值
    hfpsBlockDuration  = 2 * time.Minute         // 阻断持续时间
    hfpsBlockTable     = make(map[string]time.Time) // srcIP -> blockUntil
)

// --- Analyzer ---

type HighFreqPortScanAnalyzer struct{}

func (a *HighFreqPortScanAnalyzer) Name() string {
    return "high-freq-portscan"
}

func (a *HighFreqPortScanAnalyzer) Limit() int {
    return 0
}

func (a *HighFreqPortScanAnalyzer) NewTCP(info filter.TCPInfo, logger filter.Logger) filter.TCPStream {
    return &highFreqPortScanTCPStream{
        logger:        logger,
        srcIP:         info.SrcIP,
        dstPort:       info.DstPort,
        startTime:     time.Now(),
        closeComplete: make(chan struct{}),
    }
}

func (a *HighFreqPortScanAnalyzer) NewUDP(info filter.UDPInfo, logger filter.Logger) filter.UDPStream {
    return &highFreqPortScanUDPStream{
        logger:        logger,
        srcIP:         info.SrcIP,
        dstPort:       info.DstPort,
        startTime:     time.Now(),
        closeComplete: make(chan struct{}),
    }
}

// --- TCP Stream ---

type highFreqPortScanTCPStream struct {
    logger        filter.Logger
    srcIP         net.IP
    dstPort       uint16
    blocked       bool
    reason        string
    startTime     time.Time
    closeOnce     sync.Once
    closeComplete chan struct{}
}

func (s *highFreqPortScanTCPStream) Feed(rev bool, start bool, end bool, skip int, data []byte) (*filter.PropUpdate, bool) {
    if s.blocked {
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
                "blocked": true,
                "reason":  s.reason,
            },
        }, true
    }
    if rev {
        return nil, false
    }

    if checkAndRecordPortScan(s.srcIP, s.dstPort) {
        s.blocked = true
        s.reason = "high-freq-portscan"
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
                "blocked": true,
                "reason":  s.reason,
            },
        }, true
    }
    return nil, false
}

func (s *highFreqPortScanTCPStream) Close(limited bool) *filter.PropUpdate {
    s.closeOnce.Do(func() {
        close(s.closeComplete)
    })
    return &filter.PropUpdate{
        Type: filter.PropUpdateReplace,
        M: filter.PropMap{
            "blocked": s.blocked,
            "reason":  s.reason,
            "time":    time.Since(s.startTime).Seconds(),
        },
    }
}

// --- UDP Stream ---

type highFreqPortScanUDPStream struct {
    logger        filter.Logger
    srcIP         net.IP
    dstPort       uint16
    blocked       bool
    reason        string
    startTime     time.Time
    closeOnce     sync.Once
    closeComplete chan struct{}
}

func (s *highFreqPortScanUDPStream) Feed(rev bool, data []byte) (*filter.PropUpdate, bool) {
    if s.blocked {
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
                "blocked": true,
                "reason":  s.reason,
            },
        }, true
    }
    if rev {
        return nil, false
    }

    if checkAndRecordPortScan(s.srcIP, s.dstPort) {
        s.blocked = true
        s.reason = "high-freq-portscan"
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
                "blocked": true,
                "reason":  s.reason,
            },
        }, true
    }
    return nil, false
}

func (s *highFreqPortScanUDPStream) Close(limited bool) *filter.PropUpdate {
    s.closeOnce.Do(func() {
        close(s.closeComplete)
    })
    return &filter.PropUpdate{
        Type: filter.PropUpdateReplace,
        M: filter.PropMap{
            "blocked": s.blocked,
            "reason":  s.reason,
            "time":    time.Since(s.startTime).Seconds(),
        },
    }
}

// --- 工具函数 ---

func checkAndRecordPortScan(srcIP net.IP, dstPort uint16) bool {
    now := time.Now()
    s := srcIP.String()

    // 若已被拉黑，且未到解封时间，直接拦截
    hfpsTableLock.Lock()
    defer hfpsTableLock.Unlock()
    if unblockAt, blocked := hfpsBlockTable[s]; blocked {
        if now.Before(unblockAt) {
            return true
        }
        delete(hfpsBlockTable, s)
    }

    // 记录端口
    portMap, ok := hfpsTable[s]
    if !ok {
        portMap = make(map[uint16]time.Time)
        hfpsTable[s] = portMap
    }
    portMap[dstPort] = now

    // 清理过期端口
    validPorts := make(map[uint16]time.Time)
    for port, t := range portMap {
        if now.Sub(t) <= hfpsTimeWindow {
            validPorts[port] = t
        }
    }
    hfpsTable[s] = validPorts

    // 统计端口数
    if len(validPorts) > hfpsPortThreshold {
        hfpsBlockTable[s] = now.Add(hfpsBlockDuration)
        return true
    }
    return false
}
