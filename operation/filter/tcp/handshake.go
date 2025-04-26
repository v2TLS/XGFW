package tcp

import (
    "crypto/x509"
    "encoding/pem"
    "strings"
    "sync"
    "time"
    "encoding/binary"

    "github.com/v2TLS/XGFW/operation/filter"
    "github.com/v2TLS/XGFW/operation/filter/internal"
    "github.com/v2TLS/XGFW/operation/protocol/utils"
    "github.com/v2TLS/XGFW/operation/filter/internal/udp/quic"
)

// 确保实现接口
var (
    _ filter.UDPAnalyzer = (*GolangTLSSelfSignedAnalyzer)(nil)
    _ filter.UDPStream   = (*golangTLSSelfSignedUDPStream)(nil)
    _ filter.TCPAnalyzer = (*GolangTLSSelfSignedAnalyzer)(nil)
    _ filter.TCPStream   = (*golangTLSSelfSignedTCPStream)(nil)
)

// --- Analyzer ---

type GolangTLSSelfSignedAnalyzer struct{}

func (a *GolangTLSSelfSignedAnalyzer) Name() string {
    return "golang-tls-selfsigned"
}

func (a *GolangTLSSelfSignedAnalyzer) Limit() int {
    return 0
}

func (a *GolangTLSSelfSignedAnalyzer) NewUDP(info filter.UDPInfo, logger filter.Logger) filter.UDPStream {
    return &golangTLSSelfSignedUDPStream{
        logger:        logger,
        startTime:     time.Now(),
        closeComplete: make(chan struct{}),
    }
}

func (a *GolangTLSSelfSignedAnalyzer) NewTCP(info filter.TCPInfo, logger filter.Logger) filter.TCPStream {
    return &golangTLSSelfSignedTCPStream{
        logger:        logger,
        startTime:     time.Now(),
        closeComplete: make(chan struct{}),
        buf:           make([]byte, 0, 4096),
    }
}

// --- UDP Stream ---

type golangTLSSelfSignedUDPStream struct {
    logger        filter.Logger
    startTime     time.Time
    sni           string
    isGolangTLS   bool
    isSelfSigned  bool
    checked       bool // only check once
    blocked       bool
    closeOnce     sync.Once
    closeComplete chan struct{}
}

func (s *golangTLSSelfSignedUDPStream) Feed(rev bool, data []byte) (*filter.PropUpdate, bool) {
    if s.blocked {
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
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
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
                "blocked": true,
                "reason":  "golang-default-tls-selfsigned",
            },
        }, true
    }

    return nil, false
}

func (s *golangTLSSelfSignedUDPStream) Close(limited bool) *filter.PropUpdate {
    s.closeOnce.Do(func() {
        close(s.closeComplete)
    })
    return &filter.PropUpdate{
        Type: filter.PropUpdateReplace,
        M: filter.PropMap{
            "blocked": s.blocked,
            "reason":  "golang-default-tls-selfsigned",
            "sni":     s.sni,
            "time":    time.Since(s.startTime).Seconds(),
        },
    }
}

// --- TCP Stream ---

type golangTLSSelfSignedTCPStream struct {
    logger        filter.Logger
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

func (s *golangTLSSelfSignedTCPStream) Feed(rev bool, start bool, end bool, skip int, data []byte) (*filter.PropUpdate, bool) {
    if s.blocked {
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
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

    // 解析 ClientHello
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
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
                "blocked": true,
                "reason":  "golang-default-tls-selfsigned",
            },
        }, true
    }
    return nil, false
}

func (s *golangTLSSelfSignedTCPStream) Close(limited bool) *filter.PropUpdate {
    s.closeOnce.Do(func() {
        close(s.closeComplete)
    })
    return &filter.PropUpdate{
        Type: filter.PropUpdateReplace,
        M: filter.PropMap{
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

// TCP流量解析TLS ClientHello的辅助函数
func parseTLSClientHelloFromTCP(buf []byte) map[string]interface{} {
    // 只支持标准TLS ClientHello，不处理分片和多record
    if len(buf) < 5 || buf[0] != 0x16 {
        return nil
    }
    handshakeLen := int(buf[3])<<8 | int(buf[4])
    if len(buf) < 5+handshakeLen {
        return nil
    }
    handshake := buf[5 : 5+handshakeLen]
    if len(handshake) < 4 {
        return nil
    }
    if handshake[0] != 0x01 { // HandshakeType: ClientHello
        return nil
    }
    out := make(map[string]interface{})
    cur := 4 // skip HandshakeType(1)+length(3)
    if cur+2 > len(handshake) {
        return nil
    }
    cur += 2 // client_version
    cur += 32 // Random
    if cur >= len(handshake) {
        return nil
    }
    sidLen := int(handshake[cur])
    cur++
    cur += sidLen
    if cur+2 > len(handshake) {
        return nil
    }
    csLen := int(handshake[cur])<<8 | int(handshake[cur+1])
    cur += 2
    if cur+csLen > len(handshake) {
        return nil
    }
    cipherSuites := []interface{}{}
    for i := 0; i+1 < csLen; i += 2 {
        cs := binary.BigEndian.Uint16(handshake[cur+i : cur+i+2])
        cipherSuites = append(cipherSuites, cs)
    }
    out["CipherSuites"] = cipherSuites
    cur += csLen
    if cur >= len(handshake) {
        return nil
    }
    compLen := int(handshake[cur])
    cur++
    cur += compLen
    if cur+2 > len(handshake) {
        return nil
    }
    extLen := int(handshake[cur])<<8 | int(handshake[cur+1])
    cur += 2
    if cur+extLen > len(handshake) {
        return nil
    }
    extData := handshake[cur : cur+extLen]
    extCur := 0

    var alpnList []interface{}
    var groups []interface{}
    var sni string

    for extCur+4 <= len(extData) {
        extType := binary.BigEndian.Uint16(extData[extCur : extCur+2])
        extValLen := int(binary.BigEndian.Uint16(extData[extCur+2 : extCur+4]))
        extCur += 4
        if extCur+extValLen > len(extData) {
            break
        }
        extVal := extData[extCur : extCur+extValLen]

        switch extType {
        case 0x0000: // server_name
            if len(extVal) < 2 {
                break
            }
            nl := int(binary.BigEndian.Uint16(extVal[:2]))
            if nl+2 > len(extVal) {
                break
            }
            pos := 2
            for pos+3 <= nl+2 && pos+3 <= len(extVal) {
                nameType := extVal[pos]
                nameLen := int(binary.BigEndian.Uint16(extVal[pos+1 : pos+3]))
                pos += 3
                if pos+nameLen > len(extVal) {
                    break
                }
                if nameType == 0 {
                    sni = string(extVal[pos : pos+nameLen])
                    break
                }
                pos += nameLen
            }
        case 0x0010: // ALPN
            if len(extVal) < 2 {
                break
            }
            listLen := int(binary.BigEndian.Uint16(extVal[:2]))
            pos := 2
            for pos < 2+listLen && pos < len(extVal) {
                l := int(extVal[pos])
                pos++
                if pos+l > len(extVal) {
                    break
                }
                alpn := string(extVal[pos : pos+l])
                alpnList = append(alpnList, alpn)
                pos += l
            }
        case 0x000a: // supported_groups
            if len(extVal) < 2 {
                break
            }
            ng := int(binary.BigEndian.Uint16(extVal[:2]))
            pos := 2
            for pos+1 < 2+ng && pos+1 < len(extVal) {
                group := binary.BigEndian.Uint16(extVal[pos : pos+2])
                groups = append(groups, group)
                pos += 2
            }
        }
        extCur += extValLen
    }
    out["ALPNs"] = alpnList
    out["SupportedGroups"] = groups
    if sni != "" {
        out["SNI"] = sni
    }
    // 没有证书（ClientHello阶段）
    return out
}
