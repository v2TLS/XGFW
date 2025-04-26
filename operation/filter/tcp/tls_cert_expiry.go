package tcp

import (
    "crypto/x509"
    "encoding/pem"
    "sync"
    "time"

    "github.com/v2TLS/XGFW/operation/filter"
    "github.com/v2TLS/XGFW/operation/filter/internal"
    "github.com/v2TLS/XGFW/operation/protocol/utils"
    "github.com/v2TLS/XGFW/operation/filter/internal/udp/quic"
)

// 确保实现接口
var (
    _ filter.UDPAnalyzer = (*TLSCertExpiryAnalyzer)(nil)
    _ filter.UDPStream   = (*tlsCertExpiryUDPStream)(nil)
    _ filter.TCPAnalyzer = (*TLSCertExpiryAnalyzer)(nil)
    _ filter.TCPStream   = (*tlsCertExpiryTCPStream)(nil)
)

// --- Analyzer ---

type TLSCertExpiryAnalyzer struct{}

func (a *TLSCertExpiryAnalyzer) Name() string {
    return "tls-cert-expiry"
}

func (a *TLSCertExpiryAnalyzer) Limit() int {
    return 0
}

func (a *TLSCertExpiryAnalyzer) NewUDP(info filter.UDPInfo, logger filter.Logger) filter.UDPStream {
    return &tlsCertExpiryUDPStream{
        logger:        logger,
        startTime:     time.Now(),
        closeComplete: make(chan struct{}),
    }
}

func (a *TLSCertExpiryAnalyzer) NewTCP(info filter.TCPInfo, logger filter.Logger) filter.TCPStream {
    return &tlsCertExpiryTCPStream{
        logger:        logger,
        startTime:     time.Now(),
        closeComplete: make(chan struct{}),
        buf:           make([]byte, 0, 4096),
    }
}

// --- UDP Stream ---

type tlsCertExpiryUDPStream struct {
    logger        filter.Logger
    startTime     time.Time
    blocked       bool
    checked       bool
    reason        string
    closeOnce     sync.Once
    closeComplete chan struct{}
}

func (s *tlsCertExpiryUDPStream) Feed(rev bool, data []byte) (*filter.PropUpdate, bool) {
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

    // 用 internal.ParseTLSClientHelloMsgData 分析
    m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: pl[4:]})
    if m == nil {
        return nil, false
    }

    if !s.checked {
        s.checked = true
        // 检查证书
        if certs, ok := m["PeerCertificates"]; ok {
            if certList, ok2 := certs.([]string); ok2 && len(certList) > 0 {
                for _, certPEM := range certList {
                    if expired, why := checkCertExpiry(certPEM); expired {
                        s.blocked = true
                        s.reason = why
                        break
                    }
                }
            }
        }
        if !s.blocked {
            if certRaw, ok := m["Certificate"]; ok {
                switch certVal := certRaw.(type) {
                case string:
                    if expired, why := checkCertExpiry(certVal); expired {
                        s.blocked = true
                        s.reason = why
                    }
                case []string:
                    for _, certPEM := range certVal {
                        if expired, why := checkCertExpiry(certPEM); expired {
                            s.blocked = true
                            s.reason = why
                            break
                        }
                    }
                }
            }
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

func (s *tlsCertExpiryUDPStream) Close(limited bool) *filter.PropUpdate {
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

// --- TCP Stream ---

type tlsCertExpiryTCPStream struct {
    logger        filter.Logger
    startTime     time.Time
    blocked       bool
    checked       bool
    reason        string
    closeOnce     sync.Once
    closeComplete chan struct{}
    buf           []byte
}

func (s *tlsCertExpiryTCPStream) Feed(rev bool, start bool, end bool, skip int, data []byte) (*filter.PropUpdate, bool) {
    if s.blocked {
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
                "blocked": true,
                "reason":  s.reason,
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

    // 用 internal.ParseTLSClientHelloMsgData 分析
    m := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: s.buf})
    if m == nil {
        return nil, false
    }
    if !s.checked {
        s.checked = true
        if certs, ok := m["PeerCertificates"]; ok {
            if certList, ok2 := certs.([]string); ok2 && len(certList) > 0 {
                for _, certPEM := range certList {
                    if expired, why := checkCertExpiry(certPEM); expired {
                        s.blocked = true
                        s.reason = why
                        break
                    }
                }
            }
        }
        if !s.blocked {
            if certRaw, ok := m["Certificate"]; ok {
                switch certVal := certRaw.(type) {
                case string:
                    if expired, why := checkCertExpiry(certVal); expired {
                        s.blocked = true
                        s.reason = why
                    }
                case []string:
                    for _, certPEM := range certVal {
                        if expired, why := checkCertExpiry(certPEM); expired {
                            s.blocked = true
                            s.reason = why
                            break
                        }
                    }
                }
            }
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

func (s *tlsCertExpiryTCPStream) Close(limited bool) *filter.PropUpdate {
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

// checkCertExpiry 检查证书是否异常：即将过期(1天内)、或过期、或长期有效(>398天)，返回是否异常及原因
func checkCertExpiry(certPEM string) (expired bool, reason string) {
    block, _ := pem.Decode([]byte(certPEM))
    if block == nil {
        return false, ""
    }
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return false, ""
    }
    now := time.Now()
    // 1. 已经过期
    if now.After(cert.NotAfter) {
        return true, "tls-cert-expired"
    }
    // 2. 即将过期（24小时内）
    if cert.NotAfter.Sub(now) <= 24*time.Hour {
        return true, "tls-cert-expire-soon"
    }
    // 3. 长期有效（>398天，苹果/谷歌等大厂推荐398天为最大有效期）
    if cert.NotAfter.Sub(cert.NotBefore) > 398*24*time.Hour {
        return true, "tls-cert-long-valid"
    }
    return false, ""
}
