package tcp

import (
    "crypto/x509"
    "crypto/sha256"
    "encoding/pem"
    "fmt"
    "sync"
    "time"

    filter "github.com/v2TLS/XGFW/operation"
    "github.com/v2TLS/XGFW/operation/filter/internal"
    "github.com/v2TLS/XGFW/operation/utils"
    "github.com/v2TLS/XGFW/operation/filter/internal/udp/quic"
)

// 全局公钥指纹 -> SNI、次数 映射
var (
    pubkeyMap     = make(map[string]map[string]int) // pubkeyHash -> SNI -> count
    pubkeyMapLock sync.Mutex
    pubkeyDupThreshold = 4 // 超过4个不同SNI使用同一个公钥视为异常，可调
)

// --- Analyzer ---

type TLSPubkeyDupAnalyzer struct{}

func (a *TLSPubkeyDupAnalyzer) Name() string {
    return "tls-pubkey-dup"
}

func (a *TLSPubkeyDupAnalyzer) Limit() int {
    return 0
}

func (a *TLSPubkeyDupAnalyzer) NewUDP(info filter.UDPInfo, logger filter.Logger) filter.UDPStream {
    return &tlsPubkeyDupUDPStream{
        logger:        logger,
        startTime:     time.Now(),
        closeComplete: make(chan struct{}),
    }
}

func (a *TLSPubkeyDupAnalyzer) NewTCP(info filter.TCPInfo, logger filter.Logger) filter.TCPStream {
    return &tlsPubkeyDupTCPStream{
        logger:        logger,
        startTime:     time.Now(),
        closeComplete: make(chan struct{}),
        buf:           make([]byte, 0, 4096),
    }
}

// --- UDP Stream ---

type tlsPubkeyDupUDPStream struct {
    logger        filter.Logger
    startTime     time.Time
    checked       bool
    blocked       bool
    reason        string
    sni           string
    closeOnce     sync.Once
    closeComplete chan struct{}
}

func (s *tlsPubkeyDupUDPStream) Feed(rev bool, data []byte) (*filter.PropUpdate, bool) {
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

    pl, err := quic.ReadCryptoPayload(data)
    if err != nil || len(pl) < 4 {
        return nil, false
    }
    if pl[0] != internal.TypeClientHello {
        return nil, false
    }

    m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4:]})
    if m == nil {
        return nil, false
    }
    sni, _ := m["SNI"].(string)
    s.sni = sni

    if !s.checked {
        s.checked = true
        pubkeyHash := extractCertPubkeyHash(m)
        if pubkeyHash != "" && sni != "" {
            count := recordAndCheckPubkeyDup(pubkeyHash, sni)
            if count > pubkeyDupThreshold {
                s.blocked = true
                s.reason = fmt.Sprintf("tls-pubkey-reused:%s", pubkeyHash)
            }
        }
    }

    if s.blocked {
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
                "blocked": true,
                "reason":  s.reason,
                "sni":     s.sni,
            },
        }, true
    }
    return nil, false
}

func (s *tlsPubkeyDupUDPStream) Close(limited bool) *filter.PropUpdate {
    s.closeOnce.Do(func() {
        close(s.closeComplete)
    })
    return &filter.PropUpdate{
        Type: filter.PropUpdateReplace,
        M: filter.PropMap{
            "blocked": s.blocked,
            "reason":  s.reason,
            "sni":     s.sni,
            "time":    time.Since(s.startTime).Seconds(),
        },
    }
}

// --- TCP Stream ---

type tlsPubkeyDupTCPStream struct {
    logger        filter.Logger
    startTime     time.Time
    checked       bool
    blocked       bool
    reason        string
    sni           string
    closeOnce     sync.Once
    closeComplete chan struct{}
    buf           []byte
}

func (s *tlsPubkeyDupTCPStream) Feed(rev bool, start bool, end bool, skip int, data []byte) (*filter.PropUpdate, bool) {
    if s.blocked {
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
                "blocked": true,
                "reason":  s.reason,
                "sni":     s.sni,
            },
        }, true
    }
    if skip != 0 {
        return nil, true
    }
    if rev {
        return nil, false
    }
    if len(data) == 0 {
        return nil, false
    }
    s.buf = append(s.buf, data...)

    m := parseTLSClientHelloFromTCP(s.buf)
    if m == nil {
        return nil, false
    }
    sni, _ := m["SNI"].(string)
    s.sni = sni

    if !s.checked {
        s.checked = true
        pubkeyHash := extractCertPubkeyHash(m)
        if pubkeyHash != "" && sni != "" {
            count := recordAndCheckPubkeyDup(pubkeyHash, sni)
            if count > pubkeyDupThreshold {
                s.blocked = true
                s.reason = fmt.Sprintf("tls-pubkey-reused:%s", pubkeyHash)
            }
        }
    }
    if s.blocked {
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
                "blocked": true,
                "reason":  s.reason,
                "sni":     s.sni,
            },
        }, true
    }
    return nil, false
}

func (s *tlsPubkeyDupTCPStream) Close(limited bool) *filter.PropUpdate {
    s.closeOnce.Do(func() {
        close(s.closeComplete)
    })
    return &filter.PropUpdate{
        Type: filter.PropUpdateReplace,
        M: filter.PropMap{
            "blocked": s.blocked,
            "reason":  s.reason,
            "sni":     s.sni,
            "time":    time.Since(s.startTime).Seconds(),
        },
    }
}

// --- 工具函数 ---

func extractCertPubkeyHash(m map[string]interface{}) string {
    // 优先 PeerCertificates, 再找 Certificate
    var certPEM string
    if certs, ok := m["PeerCertificates"]; ok {
        if certList, ok2 := certs.([]string); ok2 && len(certList) > 0 {
            certPEM = certList[0]
        }
    }
    if certPEM == "" {
        if certRaw, ok := m["Certificate"]; ok {
            switch certVal := certRaw.(type) {
            case string:
                certPEM = certVal
            case []string:
                if len(certVal) > 0 {
                    certPEM = certVal[0]
                }
            }
        }
    }
    if certPEM == "" {
        return ""
    }
    block, _ := pem.Decode([]byte(certPEM))
    if block == nil {
        return ""
    }
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil || cert == nil {
        return ""
    }
    pubkey := cert.PublicKey
    pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
    if err != nil {
        return ""
    }
    sum := sha256.Sum256(pubkeyBytes)
    return fmt.Sprintf("%x", sum[:])
}

// 记录公钥指纹与SNI对应关系，返回该公钥被多少个不同SNI使用
func recordAndCheckPubkeyDup(pubkeyHash, sni string) int {
    pubkeyMapLock.Lock()
    defer pubkeyMapLock.Unlock()
    m, ok := pubkeyMap[pubkeyHash]
    if !ok {
        m = make(map[string]int)
        pubkeyMap[pubkeyHash] = m
    }
    m[sni]++
    return len(m)
}

// --- TCP流量解析TLS ClientHello的辅助函数（已实现） ---
// parseTLSClientHelloFromTCP(buf []byte) map[string]interface{}
