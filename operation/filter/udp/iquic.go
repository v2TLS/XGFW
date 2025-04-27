package udp

import (
    "sync"
    "time"

    filter "github.com/v2TLS/XGFW/operation"
    "github.com/v2TLS/XGFW/operation/filter/internal"
    "github.com/v2TLS/XGFW/operation/utils"
    "github.com/v2TLS/XGFW/operation/filter/internal/udp/quic"
    "encoding/binary"
    "strings"
)

// 确保实现接口
var (
    _ filter.UDPAnalyzer = (*QUICStrictAnalyzer)(nil)
    _ filter.UDPStream   = (*quicStrictUDPStream)(nil)
    _ filter.TCPAnalyzer = (*QUICStrictAnalyzer)(nil)
    _ filter.TCPStream   = (*quicStrictTCPStream)(nil)
)

// --- Analyzer ---

type QUICStrictAnalyzer struct{}

func (a *QUICStrictAnalyzer) Name() string {
    return "quic-strict"
}

func (a *QUICStrictAnalyzer) Limit() int {
    return 0
}

func (a *QUICStrictAnalyzer) NewUDP(info filter.UDPInfo, logger filter.Logger) filter.UDPStream {
    return &quicStrictUDPStream{
        logger:        logger,
        startTime:     time.Now(),
        closeComplete: make(chan struct{}),
    }
}

func (a *QUICStrictAnalyzer) NewTCP(info filter.TCPInfo, logger filter.Logger) filter.TCPStream {
    return &quicStrictTCPStream{
        logger:        logger,
        startTime:     time.Now(),
        closeComplete: make(chan struct{}),
        buf:           make([]byte, 0, 4096),
    }
}

// --- UDP Stream ---

type quicStrictUDPStream struct {
    logger        filter.Logger
    startTime     time.Time
    checked       bool // 是否已检查
    blocked       bool
    reason        string
    closeOnce     sync.Once
    closeComplete chan struct{}
}

func (s *quicStrictUDPStream) Feed(rev bool, data []byte) (*filter.PropUpdate, bool) {
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

    if !s.checked {
        s.checked = true
        strict, why := isStrictQUICClientHello(m)
        if !strict {
            s.blocked = true
            s.reason = why
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

func (s *quicStrictUDPStream) Close(limited bool) *filter.PropUpdate {
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

type quicStrictTCPStream struct {
    logger        filter.Logger
    startTime     time.Time
    checked       bool
    blocked       bool
    reason        string
    closeOnce     sync.Once
    closeComplete chan struct{}
    buf           []byte
}

func (s *quicStrictTCPStream) Feed(rev bool, start bool, end bool, skip int, data []byte) (*filter.PropUpdate, bool) {
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

    m := parseTLSClientHelloFromTCP(s.buf)
    if m == nil {
        return nil, false
    }
    if !s.checked {
        s.checked = true
        alpns, _ := m["ALPNs"].([]interface{})
        for _, alpn := range alpns {
            if str, ok := alpn.(string); ok && isHTTP3ALPN(str) {
                strict, why := isStrictQUICClientHello(m)
                if !strict {
                    s.blocked = true
                    s.reason = why
                    break
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

func (s *quicStrictTCPStream) Close(limited bool) *filter.PropUpdate {
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

// isStrictQUICClientHello 细化所有必要QUIC/HTTP3 ClientHello特征，严格符合IETF&主流实现（如Chrome、Firefox、Safari、Edge等）
func isStrictQUICClientHello(m map[string]interface{}) (ok bool, why string) {
    // 1. CipherSuites 必须只包含 [0x1301, 0x1302, 0x1303] 且顺序一致
    suites, ok := m["CipherSuites"].([]interface{})
    if !ok || len(suites) != 3 {
        return false, "quic-ciphersuites-mismatch"
    }
    for i, expect := range []uint16{0x1301, 0x1302, 0x1303} {
        if asUint16(suites[i]) != expect {
            return false, "quic-ciphersuites-mismatch"
        }
    }
    // 2. SupportedGroups 必须包含x25519(0x1d)且首位，后面可为secp256r1(0x17)等
    groups, ok := m["SupportedGroups"].([]interface{})
    if !ok || len(groups) < 1 || asUint16(groups[0]) != 0x1d {
        return false, "quic-x25519-missing"
    }
    // 3. ALPN 必须有且首元素为h3/h3-29/h3-32等
    alpns, ok := m["ALPNs"].([]interface{})
    if !ok || len(alpns) < 1 {
        return false, "quic-alpn-missing"
    }
    if !isHTTP3ALPN(asString(alpns[0])) {
        return false, "quic-alpn-missing"
    }
    // 4. QUICTransportParameters 必须存在，且必须包含initial_max_data, initial_max_stream_data_bidi_local等关键字段
    params, ok := m["QUICTransportParameters"].(map[string]interface{})
    if !ok {
        return false, "quic-transportparams-missing"
    }
    requiredParams := []string{
        "initial_max_data",
        "initial_max_stream_data_bidi_local",
        "initial_max_stream_data_bidi_remote",
        "initial_max_stream_data_uni",
        "initial_max_streams_bidi",
        "initial_max_streams_uni",
        "max_idle_timeout",
    }
    for _, k := range requiredParams {
        if _, found := params[k]; !found {
            return false, "quic-param-" + k + "-missing"
        }
    }
    // 5. SNI 必须存在且为合法域名（非IP/非空/非localhost等）
    sni, _ := m["SNI"].(string)
    if sni == "" || !isValidSNI(sni) {
        return false, "quic-sni-invalid"
    }
    // 6. ClientHello Extensions 需包含 signature_algorithms/key_share/supported_versions/psk_key_exchange_modes/transport_parameters
    if !hasHelloExt(m, "signature_algorithms") {
        return false, "quic-sigalgs-missing"
    }
    if !hasHelloExt(m, "key_share") {
        return false, "quic-keyshare-missing"
    }
    if !hasHelloExt(m, "supported_versions") {
        return false, "quic-versionext-missing"
    }
    if !hasHelloExt(m, "psk_key_exchange_modes") {
        return false, "quic-psk-kex-missing"
    }
    if !hasHelloExt(m, "transport_parameters") {
        return false, "quic-transportparams-missing"
    }
    // 7. GREASE机制（RFC8701）检测，主流实现会引入GREASE值，增强指纹唯一性
    if !hasGreaseValue(suites, groups, alpns) {
        return false, "quic-grease-missing"
    }
    // 8. 其它可选：User-Agent/fingerprint/实现名字段不应出现异常值
    return true, ""
}

func isHTTP3ALPN(s string) bool {
    switch s {
    case "h3", "h3-29", "h3-32", "h3-31", "h3-30", "h3-34":
        return true
    }
    return false
}

func asUint16(v interface{}) uint16 {
    switch t := v.(type) {
    case uint16:
        return t
    case int:
        return uint16(t)
    case uint8:
        return uint16(t)
    }
    return 0
}

func asString(v interface{}) string {
    switch t := v.(type) {
    case string:
        return t
    }
    return ""
}

// 判断SNI是否为标准域名
func isValidSNI(sni string) bool {
    if sni == "" ||
        strings.Contains(sni, "localhost") ||
        strings.HasPrefix(sni, "127.") ||
        strings.HasPrefix(sni, "[::1]") ||
        strings.Contains(sni, ":") ||
        strings.Count(sni, ".") < 1 {
        return false
    }
    return true
}

// 检查ClientHello扩展是否包含某字段
func hasHelloExt(m map[string]interface{}, ext string) bool {
    // 实际应在ParseTLSClientHelloMsgData返回的map中体现所有extensions
    exts, ok := m["Extensions"].([]string)
    if !ok {
        return false
    }
    for _, e := range exts {
        if e == ext {
            return true
        }
    }
    return false
}

// 检查是否有GREASE值
func hasGreaseValue(suites, groups, alpns []interface{}) bool {
    // GREASE值定义见RFC8701，常见为0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa等
    greaseVals := map[uint16]struct{}{
        0x0a0a: {}, 0x1a1a: {}, 0x2a2a: {}, 0x3a3a: {},
        0x4a4a: {}, 0x5a5a: {}, 0x6a6a: {}, 0x7a7a: {},
        0x8a8a: {}, 0x9a9a: {}, 0xaaaa: {}, 0xbaba: {},
        0xcaca: {}, 0xdada: {}, 0xeaea: {}, 0xfafa: {},
    }
    found := false
    for _, s := range suites {
        if _, ok := greaseVals[asUint16(s)]; ok {
            found = true
            break
        }
    }
    for _, g := range groups {
        if _, ok := greaseVals[asUint16(g)]; ok {
            found = true
            break
        }
    }
    for _, a := range alpns {
        s := asString(a)
        if strings.HasPrefix(s, "grease-") {
            found = true
            break
        }
    }
    return found
}

// --- TCP流量解析TLS ClientHello的辅助函数 ---
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
    var exts []string

    // for strictness, record all present extensions
    for extCur+4 <= len(extData) {
        extType := binary.BigEndian.Uint16(extData[extCur : extCur+2])
        extValLen := int(binary.BigEndian.Uint16(extData[extCur+2 : extCur+4]))
        extCur += 4
        if extCur+extValLen > len(extData) {
            break
        }
        extVal := extData[extCur : extCur+extValLen]

        switch extType {
        case 0x0000:
            exts = append(exts, "server_name")
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
        case 0x0010:
            exts = append(exts, "alpn")
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
        case 0x000a:
            exts = append(exts, "supported_groups")
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
        case 0x000d:
            exts = append(exts, "signature_algorithms")
        case 0x0033:
            exts = append(exts, "key_share")
        case 0x002b:
            exts = append(exts, "supported_versions")
        case 0x002d:
            exts = append(exts, "psk_key_exchange_modes")
        case 0x0039:
            exts = append(exts, "transport_parameters")
        }
        extCur += extValLen
    }
    out["ALPNs"] = alpnList
    out["SupportedGroups"] = groups
    if sni != "" {
        out["SNI"] = sni
    }
    out["Extensions"] = exts
    // 没有证书（ClientHello阶段）
    return out
}
