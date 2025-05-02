package tcp

import (
    "bytes"
    "fmt"
    "net"
    "sync"
    "time"

    filter "github.com/v2TLS/XGFW/operation"
)

// 允许的SSH Banner和算法指纹（可根据实际需求调整）
var (
    allowedBanners = []string{
        "SSH-2.0-OpenSSH_8.4",
        "SSH-2.0-OpenSSH_9.0",
        "SSH-2.0-OpenSSH_8.6",
        // 可补充标准banner
    }
    allowedKexAlgos = []string{
        "curve25519-sha256",
        "ecdh-sha2-nistp256",
        "diffie-hellman-group-exchange-sha256",
        // 可补充标准算法
    }
    allowedHostKeyAlgos = []string{
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ecdsa-sha2-nistp256",
        "ssh-ed25519",
        // 可补充标准算法
    }
)

// --- Analyzer ---

type SSHBannerAlgAnalyzer struct{}

func (a *SSHBannerAlgAnalyzer) Name() string {
    return "ssh-banner-alg"
}

func (a *SSHBannerAlgAnalyzer) Limit() int {
    return 0
}

func (a *SSHBannerAlgAnalyzer) NewTCP(info filter.TCPInfo, logger filter.Logger) filter.TCPStream {
    return &sshBannerAlgTCPStream{
        logger:        logger,
        startTime:     time.Now(),
        srcIP:         info.SrcIP,
        dstPort:       info.DstPort,
        buf:           make([]byte, 0, 1024),
        closeComplete: make(chan struct{}),
    }
}

// --- TCP Stream ---

type sshBannerAlgTCPStream struct {
    logger        filter.Logger
    startTime     time.Time
    srcIP         net.IP
    dstPort       uint16
    checked       bool
    blocked       bool
    reason        string
    banner        string
    closeOnce     sync.Once
    closeComplete chan struct{}
    buf           []byte
}

func (s *sshBannerAlgTCPStream) Feed(rev bool, start bool, end bool, skip int, data []byte) (*filter.PropUpdate, bool) {
    if s.blocked {
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
                "blocked": true,
                "reason":  s.reason,
                "banner":  s.banner,
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
    // 检查SSH Banner（一般首包内）
    if !s.checked && len(s.buf) >= 8 {
        line, ok := parseSSHBannerLine(s.buf)
        if ok {
            s.banner = line
            if !isSSHBannerAllowed(line) {
                s.blocked = true
                s.reason = "ssh-banner-forbidden"
                return &filter.PropUpdate{
                    Type: filter.PropUpdateReplace,
                    M: filter.PropMap{
                        "blocked": true,
                        "reason":  s.reason,
                        "banner":  s.banner,
                    },
                }, true
            }
            s.checked = true
        }
    }
    // 检查算法协商包（KEXINIT），通常在banner之后
    if s.checked && !s.blocked {
        kexAlgos, hostKeyAlgos, ok := parseSSHKexAlgos(s.buf)
        if ok {
            if !isSSHAlgoAllowed(kexAlgos, allowedKexAlgos) ||
                !isSSHAlgoAllowed(hostKeyAlgos, allowedHostKeyAlgos) {
                s.blocked = true
                s.reason = "ssh-algo-forbidden"
                return &filter.PropUpdate{
                    Type: filter.PropUpdateReplace,
                    M: filter.PropMap{
                        "blocked": true,
                        "reason":  s.reason,
                        "banner":  s.banner,
                    },
                }, true
            }
        }
    }
    return nil, false
}

func (s *sshBannerAlgTCPStream) Close(limited bool) *filter.PropUpdate {
    s.closeOnce.Do(func() {
        close(s.closeComplete)
    })
    return &filter.PropUpdate{
        Type: filter.PropUpdateReplace,
        M: filter.PropMap{
            "blocked": s.blocked,
            "reason":  s.reason,
            "banner":  s.banner,
            "time":    time.Since(s.startTime).Seconds(),
        },
    }
}

// --- 工具函数 ---

// parseSSHBannerLine 提取SSH Banner字符串
func parseSSHBannerLine(buf []byte) (string, bool) {
    if !bytes.HasPrefix(buf, []byte("SSH-")) {
        return "", false
    }
    if idx := bytes.IndexByte(buf, '\n'); idx != -1 && idx < 512 {
        line := string(bytes.TrimSpace(buf[:idx]))
        return line, true
    }
    return "", false
}

// isSSHBannerAllowed 判断banner是否在允许列表
func isSSHBannerAllowed(banner string) bool {
    for _, allowed := range allowedBanners {
        if banner == allowed {
            return true
        }
    }
    return false
}

// parseSSHKexAlgos 粗略解析SSH KEXINIT，提取算法协商字段（仅作结构演示，生产建议用专用库）
func parseSSHKexAlgos(buf []byte) (kexAlgos []string, hostKeyAlgos []string, ok bool) {
    // SSH KEXINIT包特征: 0x14 (SSH_MSG_KEXINIT), 后跟算法列表(以逗号分隔)
    idx := bytes.Index(buf, []byte{0x14})
    if idx < 0 || len(buf) < idx+20 {
        return nil, nil, false
    }
    rest := buf[idx+1:]
    // 跳过cookie(16字节)
    if len(rest) < 16+4 {
        return nil, nil, false
    }
    r := rest[16:]
    // 取出kex_algorithms
    kexLen := int(binaryBigEndianUint32(r[:4]))
    if len(r) < 4+kexLen+4 {
        return nil, nil, false
    }
    kexAlgos = splitCommaList(string(r[4 : 4+kexLen]))
    r = r[4+kexLen:]
    // 取出server_host_key_algorithms
    hostkeyLen := int(binaryBigEndianUint32(r[:4]))
    if len(r) < 4+hostkeyLen {
        return kexAlgos, nil, true // 部分包
    }
    hostKeyAlgos = splitCommaList(string(r[4 : 4+hostkeyLen]))
    return kexAlgos, hostKeyAlgos, true
}

func binaryBigEndianUint32(b []byte) uint32 {
    return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func splitCommaList(s string) []string {
    var out []string
    for _, v := range bytes.Split([]byte(s), []byte(",")) {
        if len(v) > 0 {
            out = append(out, string(v))
        }
    }
    return out
}

// isSSHAlgoAllowed 判断算法支持列表是否合法
func isSSHAlgoAllowed(algos, allowed []string) bool {
    for _, alg := range algos {
        found := false
        for _, allow := range allowed {
            if alg == allow {
                found = true
                break
            }
        }
        if !found {
            return false
        }
    }
    return true
}
