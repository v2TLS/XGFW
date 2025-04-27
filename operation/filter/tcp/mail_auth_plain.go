package tcp

import (
    "bytes"
    "sync"
    "time"

    filter "github.com/v2TLS/XGFW/operation"
)

// --- 确保实现接口 ---
var (
    _ filter.TCPAnalyzer = (*MailAuthPlainAnalyzer)(nil)
    _ filter.TCPStream   = (*mailAuthPlainStream)(nil)
)

// --- Analyzer ---

type MailAuthPlainAnalyzer struct{}

func (a *MailAuthPlainAnalyzer) Name() string {
    return "mail-auth-plain"
}

func (a *MailAuthPlainAnalyzer) Limit() int {
    // 邮件通常不大，128KB足够
    return 128 * 1024
}

func (a *MailAuthPlainAnalyzer) NewTCP(info filter.TCPInfo, logger filter.Logger) filter.TCPStream {
    return &mailAuthPlainStream{
        logger:        logger,
        startTime:     time.Now(),
        closeComplete: make(chan struct{}),
        buf:           make([]byte, 0, 4096),
    }
}

// --- Stream ---

type mailAuthPlainStream struct {
    logger        filter.Logger
    startTime     time.Time
    blocked       bool
    foundPlain    bool
    closeOnce     sync.Once
    closeComplete chan struct{}
    buf           []byte
    isSMTP        bool
    isPOP3        bool
    isIMAP        bool
}

func (s *mailAuthPlainStream) Feed(rev, start, end bool, skip int, data []byte) (*filter.PropUpdate, bool) {
    if s.blocked {
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
                "blocked": true,
                "reason":  "mail-auth-plain-detected",
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

    // 检测协议类型
    if !s.isSMTP && !s.isPOP3 && !s.isIMAP {
        s.isSMTP = bytes.Contains(bytes.ToUpper(s.buf), []byte("EHLO")) ||
            bytes.Contains(bytes.ToUpper(s.buf), []byte("HELO"))
        s.isPOP3 = bytes.Contains(bytes.ToUpper(s.buf), []byte("USER ")) &&
            bytes.Contains(bytes.ToUpper(s.buf), []byte("PASS "))
        s.isIMAP = bytes.Contains(bytes.ToUpper(s.buf), []byte("LOGIN "))
    }

    // 检测明文认证
    if s.isSMTP {
        // SMTP AUTH PLAIN/LOGIN
        if bytes.Contains(bytes.ToUpper(s.buf), []byte("AUTH PLAIN")) ||
            bytes.Contains(bytes.ToUpper(s.buf), []byte("AUTH LOGIN")) {
            s.foundPlain = true
        }
    }
    if s.isPOP3 {
        // POP3 USER/PASS 明文
        if bytes.Contains(bytes.ToUpper(s.buf), []byte("USER ")) &&
            bytes.Contains(bytes.ToUpper(s.buf), []byte("PASS ")) {
            s.foundPlain = true
        }
    }
    if s.isIMAP {
        // IMAP LOGIN 明文
        if bytes.Contains(bytes.ToUpper(s.buf), []byte(" LOGIN ")) {
            s.foundPlain = true
        }
    }

    if s.foundPlain {
        s.blocked = true
        return &filter.PropUpdate{
            Type: filter.PropUpdateReplace,
            M: filter.PropMap{
                "blocked":    true,
                "reason":     "mail-auth-plain-detected",
                "protocol":   s.getProto(),
                "timestamp":  time.Now().Format(time.RFC3339),
            },
        }, true
    }
    return nil, false
}

func (s *mailAuthPlainStream) Close(limited bool) *filter.PropUpdate {
    s.closeOnce.Do(func() {
        close(s.closeComplete)
    })
    return &filter.PropUpdate{
        Type: filter.PropUpdateReplace,
        M: filter.PropMap{
            "blocked":  s.blocked,
            "reason":   "mail-auth-plain-detected",
            "protocol": s.getProto(),
            "time":     time.Since(s.startTime).Seconds(),
        },
    }
}

func (s *mailAuthPlainStream) getProto() string {
    if s.isSMTP {
        return "smtp"
    }
    if s.isPOP3 {
        return "pop3"
    }
    if s.isIMAP {
        return "imap"
    }
    return ""
}
