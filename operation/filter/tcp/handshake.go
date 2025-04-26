package tcp

import (
    "crypto/x509"
    "encoding/pem"
    "strings"
    "sync"
    "time"

    "github.com/v2TLS/XGFW/operation/filter"
    "github.com/v2TLS/XGFW/operation/filter/internal"
    "github.com/v2TLS/XGFW/operation/filter/utils"
)

// 确保实现接口
var (
    _ analyzer.UDPAnalyzer = (*GolangTLSSelfSignedAnalyzer)(nil)
    _ analyzer.UDPStream   = (*golangTLSSelfSignedUDPStream)(nil)
    _ analyzer.TCPAnalyzer = (*GolangTLSSelfSignedAnalyzer)(nil)
    _ analyzer.TCPStream   = (*golangTLSSelfSignedTCPStream)(nil)
)

// --- Analyzer ---

type GolangTLSSelfSignedAnalyzer struct{}

func (a *GolangTLSSelfSignedAnalyzer) Name() string {
    return "golang-tls-selfsigned"
}

func (a *GolangTLSSelfSignedAnalyzer) Limit() int {
    return 0
}

func (a *GolangTLSSelfSignedAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
    return &golangTLSSelfSignedUDPStream{
        logger:        logger,
        startTime:     time.Now(),
        closeComplete: make(chan struct{}),
    }
}

func (a *GolangTLSSelfSignedAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    return &golangTLSSelfSignedTCPStream{
        logger:        logger,
        startTime:     time.Now(),
        closeComplete: make(chan struct{}),
        buf:           make([]byte, 0, 4096),
    }
}

// --- UDP Stream ---

type golangTLSSelfSignedUDPStream struct {
    logger        analyzer.Logger
    startTime     time.Time
    sni           string
    isGolangTLS   bool
    isSelfSigned  bool
    checked       bool // only check once
    blocked       bool
    closeOnce     sync.Once
    closeComplete chan struct{}
}

func (s *golangTLSSelfSignedUDPStream) Feed(rev bool, data []byte) (*analyzer.PropUpdate, bool) {
    if s.blocked {
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "blocked": true,
                "reason":  "golang-default-tls-selfsigned",
            },
        }, true
    }

    // 只处理客户端流量
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

    // 检查是否为golang默认指纹
    if isGolangQuicGoFingerprint(m) {
        s.isGolangTLS = true
    }

    // 检查证书，仅第一次检测
    if !s.checked {
        s.checked = true
        if certs, ok := m["PeerCertificates"]; ok {
            // 假定PeerCertificates字段是[]string, PEM编码
            if certList, ok2 := certs.([]string); ok2 && len(certList) > 0 {
                for _, certPEM := range certList {
                    if isSelfSignedCert(certPEM) {
                        s.isSelfSigned = true
                        break
                    }
                }
            }
        }
        // 也可能包含"Certificate"字段, 兼容此情况
        if !s.isSelfSigned {
            if certRaw, ok := m["Certificate"]; ok {
                switch certVal := certRaw.(type) {
                case string:
                    if isSelfSignedCert(certVal) {
                        s.isSelfSigned = true
                    }
                case []string:
                    for _, certPEM := range certVal {
                        if isSelfSignedCert(certPEM) {
                            s.isSelfSigned = true
                            break
                        }
                    }
                }
            }
        }
    }

    if s.isGolangTLS && s.isSelfSigned {
        s.blocked = true
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "blocked": true,
                "reason":  "golang-default-tls-selfsigned",
            },
        }, true
    }

    return nil, false
}

func (s *golangTLSSelfSignedUDPStream) Close(limited bool) *analyzer.PropUpdate {
    s.closeOnce.Do(func() {
        close(s.closeComplete)
    })
    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateReplace,
        M: analyzer.PropMap{
            "blocked": s.blocked,
            "reason":  "golang-default-tls-selfsigned",
            "sni":     s.sni,
            "time":    time.Since(s.startTime).Seconds(),
        },
    }
}

// --- TCP Stream ---

type golangTLSSelfSignedTCPStream struct {
    logger        analyzer.Logger
    startTime     time.Time
    sni           string
    isGolangTLS   bool
    isSelfSigned  bool
    checked       bool // only check once
    blocked       bool
    closeOnce     sync.Once
    closeComplete chan struct{}
    buf           []byte
}

func (s *golangTLSSelfSignedTCPStream) Feed(rev bool, start bool, end bool, skip int, data []byte) (*analyzer.PropUpdate, bool) {
    if s.blocked {
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "blocked": true,
                "reason":  "golang-default-tls-selfsigned",
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

    // 这里只尝试解析 ClientHello，实际生产建议用完整TLS解析库
    m := parseTLSClientHelloFromTCP(s.buf)
    if m == nil {
        return nil, false
    }
    if isGolangQuicGoFingerprint(m) {
        s.isGolangTLS = true
    }
    if !s.checked {
        s.checked = true
        if certs, ok := m["PeerCertificates"]; ok {
            if certList, ok2 := certs.([]string); ok2 && len(certList) > 0 {
                for _, certPEM := range certList {
                    if isSelfSignedCert(certPEM) {
                        s.isSelfSigned = true
                        break
                    }
                }
            }
        }
        if !s.isSelfSigned {
            if certRaw, ok := m["Certificate"]; ok {
                switch certVal := certRaw.(type) {
                case string:
                    if isSelfSignedCert(certVal) {
                        s.isSelfSigned = true
                    }
                case []string:
                    for _, certPEM := range certVal {
                        if isSelfSignedCert(certPEM) {
                            s.isSelfSigned = true
                            break
                        }
                    }
                }
            }
        }
    }
    if s.isGolangTLS && s.isSelfSigned {
        s.blocked = true
        return &analyzer.PropUpdate{
            Type: analyzer.PropUpdateReplace,
            M: analyzer.PropMap{
                "blocked": true,
                "reason":  "golang-default-tls-selfsigned",
            },
        }, true
    }
    return nil, false
}

func (s *golangTLSSelfSignedTCPStream) Close(limited bool) *analyzer.PropUpdate {
    s.closeOnce.Do(func() {
        close(s.closeComplete)
    })
    return &analyzer.PropUpdate{
        Type: analyzer.PropUpdateReplace,
        M: analyzer.PropMap{
            "blocked": s.blocked,
            "reason":  "golang-default-tls-selfsigned",
            "sni":     s.sni,
            "time":    time.Since(s.startTime).Seconds(),
        },
    }
}

// --- 工具函数 ---

// 独立实现golang quic-go指纹检测
func isGolangQuicGoFingerprint(m map[string]interface{}) bool {
    // 1. CipherSuites: [0x1301, 0x1302, 0x1303]
    // 2. SupportedGroups: [0x1d, ...]
    // 3. ALPNs: ["h3", ...]
    // 4. QUICTransportParameters 存在
    suites, ok := m["CipherSuites"].([]interface{})
    if !ok || len(suites) < 3 {
        return false
    }
    expectedSuites := []uint16{0x1301, 0x1302, 0x1303}
    for i := 0; i < 3; i++ {
        var v uint16
        switch val := suites[i].(type) {
        case uint16:
            v = val
        case int:
            v = uint16(val)
        default:
            return false
        }
        if v != expectedSuites[i] {
            return false
        }
    }
    groups, ok := m["SupportedGroups"].([]interface{})
    hasX25519 := false
    if ok && len(groups) > 0 {
        for _, g := range groups {
            var gv int
            switch t := g.(type) {
            case int:
                gv = t
            case uint16:
                gv = int(t)
            }
            if gv == 0x1d {
                hasX25519 = true
                break
            }
        }
    }
    if !hasX25519 {
        return false
    }
    alpns, ok := m["ALPNs"].([]interface{})
    hasH3 := false
    if ok && len(alpns) > 0 {
        for _, a := range alpns {
            if s, ok := a.(string); ok && (s == "h3" || s == "h3-29" || s == "h3-32") {
                hasH3 = true
                break
            }
        }
    }
    if !hasH3 {
        return false
    }
    if _, ok := m["QUICTransportParameters"]; !ok {
        return false
    }
    return true
}

// 判断PEM编码证书是否为自签名证书（并不被系统信任）
func isSelfSignedCert(certPEM string) bool {
    block, _ := pem.Decode([]byte(certPEM))
    if block == nil {
        return false
    }
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return false
    }
    // 检查是否自签名
    if cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
        roots, err := x509.SystemCertPool()
        if err == nil && roots != nil {
            opts := x509.VerifyOptions{
                Roots: roots,
            }
            if _, err := cert.Verify(opts); err == nil {
                // 能验证成功，说明是受信任CA，不视为自签名
                return false
            }
        }
        return true
    }
    if strings.TrimSpace(cert.Issuer.String()) == strings.TrimSpace(cert.Subject.String()) {
        roots, err := x509.SystemCertPool()
        if err == nil && roots != nil {
            opts := x509.VerifyOptions{
                Roots: roots,
            }
            if _, err := cert.Verify(opts); err == nil {
                return false
            }
        }
        return true
    }
    return false
}

// TCP流量解析TLS ClientHello的辅助函数（建议你实现或复用包内解析逻辑）
func parseTLSClientHelloFromTCP(buf []byte) map[string]interface{} {
    // 这里只能示意，实际应调用真正的TLS ClientHello解析
    // return internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: buf})
    return nil // TODO: 实现或调用已有代码
}
