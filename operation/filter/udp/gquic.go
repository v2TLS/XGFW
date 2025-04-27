package tcp

import (
    "sync"
    "time"
    "bytes"
    "encoding/binary"
    filter "github.com/v2TLS/XGFW/operation"
    "github.com/v2TLS/XGFW/operation/filter/internal"
    "github.com/v2TLS/XGFW/operation/utils"
    "github.com/v2TLS/XGFW/operation/filter/internal/udp/quic"
)

// 确保实现接口
var (
    _ filter.UDPAnalyzer = (*GQUICStrictOnlyAnalyzer)(nil)
    _ filter.UDPStream   = (*gquicStrictOnlyUDPStream)(nil)
)

// --- Analyzer ---

type GQUICStrictOnlyAnalyzer struct{}

func (a *GQUICStrictOnlyAnalyzer) Name() string {
    return "gquic-strict-only"
}

func (a *GQUICStrictOnlyAnalyzer) Limit() int {
    return 0
}

func (a *GQUICStrictOnlyAnalyzer) NewUDP(info filter.UDPInfo, logger filter.Logger) filter.UDPStream {
    return &gquicStrictOnlyUDPStream{
        logger:        logger,
        startTime:     time.Now(),
        closeComplete: make(chan struct{}),
    }
}

// --- UDP Stream ---

type gquicStrictOnlyUDPStream struct {
    logger        filter.Logger
    startTime     time.Time
    checked       bool
    blocked       bool
    reason        string
    closeOnce     sync.Once
    closeComplete chan struct{}
}

func (s *gquicStrictOnlyUDPStream) Feed(rev bool, data []byte) (*filter.PropUpdate, bool) {
    if s.blocked {
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
                "blocked": true,
                "reason":  s.reason,
            },
        }, true
    }

    // 只处理客户端流量
    if rev {
        return nil, false
    }

    // 检查是否为标准 gQUIC Client Hello（仅放行标准gQUIC，拦截其余所有quic/ietf quic）
    if !s.checked {
        s.checked = true
        if !isStandardGQUICClientHello(data) {
            s.blocked = true
            s.reason = "not-gquic-or-nonstandard-gquic"
        }
    }

    if s.blocked {
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

func (s *gquicStrictOnlyUDPStream) Close(limited bool) *filter.PropUpdate {
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

// isStandardGQUICClientHello 判断数据包是否为标准gQUIC Client Hello（仅放行标准gQUIC，拦截IETF QUIC与其它所有实现）
func isStandardGQUICClientHello(data []byte) bool {
    // gQUIC的握手包格式与IETF QUIC完全不同，特征如下：
    // 1. 第一个字节为标志位，最高位为1表示long header（Client Hello等），低7位为type
    // 2. 版本号为4字节（如 "Q039", "Q043", "Q046", "Q050"等），ASCII可读
    // 3. 包内有明显的"CHLO"字符串
    // 4. 没有标准TLS ClientHello结构

    if len(data) < 9 {
        return false
    }
    // gQUIC header: [flags|connID(8)|version(4)|...]
    // flags: 高位为1
    flags := data[0]
    if (flags & 0x80) == 0 { // 不是long header
        return false
    }
    // 检查version
    version := string(data[9:13])
    // 常见gQUIC版本
    gquicVers := map[string]struct{}{
        "Q039": {}, "Q043": {}, "Q044": {}, "Q046": {}, "Q050": {},
        "Q035": {}, "Q036": {}, "Q037": {}, "Q038": {}, "Q040": {}, "Q041": {}, "Q042": {},
    }
    if _, ok := gquicVers[version]; !ok {
        return false
    }
    // 检查payload内有CHLO指纹
    // gQUIC CHLO通常出现在包头后不远处
    idx := bytes.Index(data, []byte("CHLO"))
    if idx < 0 || idx > 100 {
        return false
    }
    // 排除IETF QUIC: IETF QUIC通常在payload前8或9字节出现0x00000001等版本号, 并且没有"CHLO"
    if data[9] == 0 && data[10] == 0 && data[11] == 0 && data[12] == 1 {
        return false // IETF QUIC version negotiation
    }
    // 进一步排除包含标准TLS ClientHello特征的包（如0x16, 0x0301等TLS开头）
    if len(data) > idx+4 && data[idx+4] == 0x16 && data[idx+5] == 0x03 {
        return false
    }
    // 检查是否为标准gQUIC ClientHello type
    // gQUIC type: 0x01 = Client Hello
    if (flags & 0x7F) != 0x01 {
        return false
    }
    // 通过全部检查，判定为标准gQUIC Client Hello
    return true
}
