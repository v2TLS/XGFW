package tcp

import (
    "bytes"
    "encoding/binary"
    "net"
    "sync"
    "time"

    filter "github.com/v2TLS/XGFW/operation"
)

// 允许的SSH Banner和算法指纹（2024年主流安全实现，OpenSSH/Dropbear/Win32-OpenSSH/最新商业设备等）
var (
    allowedBanners = []string{
        // OpenSSH
        "SSH-2.0-OpenSSH_8.4",
        "SSH-2.0-OpenSSH_8.6",
        "SSH-2.0-OpenSSH_8.7",
        "SSH-2.0-OpenSSH_8.8",
        "SSH-2.0-OpenSSH_8.9",
        "SSH-2.0-OpenSSH_9.0",
        "SSH-2.0-OpenSSH_9.1",
        "SSH-2.0-OpenSSH_9.2",
        "SSH-2.0-OpenSSH_9.3",
        "SSH-2.0-OpenSSH_9.4",
        "SSH-2.0-OpenSSH_9.5",
        "SSH-2.0-OpenSSH_9.6",
        // Dropbear
        "SSH-2.0-dropbear_2022.83",
        "SSH-2.0-dropbear_2024.85",
        // Win32-OpenSSH
        "SSH-2.0-Win32-OpenSSH_8.9.1.0",
        "SSH-2.0-Win32-OpenSSH_9.3.1.0",
        // Commercial/Appliance (常见设备)
        "SSH-2.0-Cisco-1.29",
        "SSH-2.0-Cisco-1.25",
        "SSH-2.0-ROSSSH",
        "SSH-2.0-Granados-1.0",    // Windows PowerShell/VSCode
        // 部分云服务
        "SSH-2.0-Paramiko_3.4.0",  // AWS/Azure SSM等自动化
        // 允许前缀匹配（如部分设备/云平台/运维场景）
    }
    allowedBannerPrefixes = []string{
        "SSH-2.0-OpenSSH_8.",
        "SSH-2.0-OpenSSH_9.",
        "SSH-2.0-dropbear_2022.",
        "SSH-2.0-dropbear_2024.",
        "SSH-2.0-Win32-OpenSSH_",
        "SSH-2.0-Cisco-",
        "SSH-2.0-ROSSSH",
        "SSH-2.0-Granados-",
        "SSH-2.0-Paramiko_",
    }
    allowedKexAlgos = []string{
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group-exchange-sha256",
        // 如需兼容部分设备可加 "diffie-hellman-group14-sha256"
        "sntrup761x25519-sha512@openssh.com",
    }
    allowedHostKeyAlgos = []string{
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "ssh-ed25519",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    }
    allowedCiphers = []string{
        "chacha20-poly1305@openssh.com",
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        // 如需兼容部分设备可加 "aes128-cbc", "3des-cbc"
    }
    allowedMACs = []string{
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-512",
        "umac-64-etm@openssh.com",
        "umac-128-etm@openssh.com",
        "umac-64@openssh.com",
        "umac-128@openssh.com",
    }
    allowedCompAlgos = []string{
        "none",
        "zlib@openssh.com",
        "zlib",
    }
    allowedLanguages = []string{"", "en-US"}
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
        buf:           make([]byte, 0, 4096),
        closeComplete: make(chan struct{}),
    }
}

// --- TCP Stream ---

type sshBannerAlgTCPStream struct {
    logger        filter.Logger
    startTime     time.Time
    srcIP         net.IP
    dstPort       uint16
    checkedBanner bool
    checkedKEX    bool
    blocked       bool
    reason        string
    banner        string
    details       map[string][]string
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
                "details": s.details,
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
    if !s.checkedBanner && len(s.buf) >= 8 {
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
                        "details": s.details,
                    },
                }, true
            }
            s.checkedBanner = true
        }
    }
    // 检查算法协商包（KEXINIT），通常在banner之后
    if s.checkedBanner && !s.checkedKEX && !s.blocked {
        kexinfo, ok := parseSSHKexInitFull(s.buf)
        if ok {
            s.details = kexinfo
            if !isSSHAlgoAllowed(kexinfo["kex_algorithms"], allowedKexAlgos) {
                s.blocked = true
                s.reason = "ssh-kexalgo-forbidden"
            } else if !isSSHAlgoAllowed(kexinfo["server_host_key_algorithms"], allowedHostKeyAlgos) {
                s.blocked = true
                s.reason = "ssh-hostkeyalgo-forbidden"
            } else if !isSSHAlgoAllowed(kexinfo["encryption_algorithms_client_to_server"], allowedCiphers) ||
                      !isSSHAlgoAllowed(kexinfo["encryption_algorithms_server_to_client"], allowedCiphers) {
                s.blocked = true
                s.reason = "ssh-cipher-forbidden"
            } else if !isSSHAlgoAllowed(kexinfo["mac_algorithms_client_to_server"], allowedMACs) ||
                      !isSSHAlgoAllowed(kexinfo["mac_algorithms_server_to_client"], allowedMACs) {
                s.blocked = true
                s.reason = "ssh-mac-forbidden"
            } else if !isSSHAlgoAllowed(kexinfo["compression_algorithms_client_to_server"], allowedCompAlgos) ||
                      !isSSHAlgoAllowed(kexinfo["compression_algorithms_server_to_client"], allowedCompAlgos) {
                s.blocked = true
                s.reason = "ssh-comp-forbidden"
            } else if !isSSHAlgoAllowed(kexinfo["languages_client_to_server"], allowedLanguages) ||
                      !isSSHAlgoAllowed(kexinfo["languages_server_to_client"], allowedLanguages) {
                s.blocked = true
                s.reason = "ssh-lang-forbidden"
            }
            s.checkedKEX = true
            if s.blocked {
                return &filter.PropUpdate{
                    Type: filter.PropUpdateReplace,
                    M: filter.PropMap{
                        "blocked": true,
                        "reason":  s.reason,
                        "banner":  s.banner,
                        "details": s.details,
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
            "details": s.details,
            "time":    time.Since(s.startTime).Seconds(),
        },
    }
}

// --- 工具函数 ---
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

func isSSHBannerAllowed(banner string) bool {
    for _, allowed := range allowedBanners {
        if banner == allowed {
            return true
        }
    }
    for _, prefix := range allowedBannerPrefixes {
        if len(banner) >= len(prefix) && banner[:len(prefix)] == prefix {
            return true
        }
    }
    return false
}

// parseSSHKexInitFull 完整解析SSH_MSG_KEXINIT协商所有算法字段，返回map
func parseSSHKexInitFull(buf []byte) (map[string][]string, bool) {
    idx := bytes.Index(buf, []byte{0x14})
    if idx < 0 || len(buf) < idx+20 {
        return nil, false
    }
    rest := buf[idx+1:]
    // 跳过cookie(16字节)
    if len(rest) < 16+4 {
        return nil, false
    }
    r := rest[16:]
    result := make(map[string][]string)
    fields := []string{
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_algorithms_client_to_server",
        "encryption_algorithms_server_to_client",
        "mac_algorithms_client_to_server",
        "mac_algorithms_server_to_client",
        "compression_algorithms_client_to_server",
        "compression_algorithms_server_to_client",
        "languages_client_to_server",
        "languages_server_to_client",
    }
    for _, field := range fields {
        if len(r) < 4 {
            return result, false
        }
        l := int(binary.BigEndian.Uint32(r[:4]))
        r = r[4:]
        if len(r) < l {
            return result, false
        }
        algos := splitCommaList(string(r[:l]))
        result[field] = algos
        r = r[l:]
    }
    // 跳过first_kex_packet_follows(1字节)与保留字节(4字节)
    return result, true
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

// isSSHAlgoAllowed 判断算法或参数支持列表是否合法（全部都要在允许列表）
func isSSHAlgoAllowed(algos, allowed []string) bool {
    if len(algos) == 0 {
        return true // 部分字段允许为空
    }
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
