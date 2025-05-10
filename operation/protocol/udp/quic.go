package udp

import (
	"github.com/v2TLS/XGFW/operation"
	"github.com/v2TLS/XGFW/operation/protocol/internal"
	"github.com/v2TLS/XGFW/operation/protocol/udp/internal/quic"
	"github.com/v2TLS/XGFW/operation/utils"
)

const (
	quicInvalidCountThreshold = 4
)

var (
	_ analyzer.UDPAnalyzer = (*QUICAnalyzer)(nil)
	_ analyzer.UDPStream   = (*quicStream)(nil)
)

type QUICAnalyzer struct{}

func (a *QUICAnalyzer) Name() string {
	return "quic"
}

func (a *QUICAnalyzer) Limit() int {
	return 0
}

func (a *QUICAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	return &quicStream{logger: logger}
}

type quicStream struct {
	logger       analyzer.Logger
	invalidCount int

	reqBuf     *utils.ByteBuffer
	reqMap     analyzer.PropMap
	reqUpdated bool
	reqLSM     *utils.LinearStateMachine
	reqDone    bool

	respBuf     *utils.ByteBuffer
	respMap     analyzer.PropMap
	respUpdated bool
	respLSM     *utils.LinearStateMachine
	respDone    bool

	clientHelloLen int
	serverHelloLen int
}

func (s *quicStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	if s.reqBuf == nil {
		s.reqBuf = &utils.ByteBuffer{}
		s.respBuf = &utils.ByteBuffer{}
		s.reqLSM = utils.NewLinearStateMachine(
			s.quicClientHelloPreprocess,
			s.parseClientHelloData,
		)
		s.respLSM = utils.NewLinearStateMachine(
			s.quicServerHelloPreprocess,
			s.parseServerHelloData,
		)
	}
	if len(data) == 0 {
		return nil, false
	}
	var update *analyzer.PropUpdate
	var cancelled bool
	if rev {
		s.respBuf.Append(data)
		s.respUpdated = false
		cancelled, s.respDone = s.respLSM.Run()
		if s.respUpdated {
			update = &analyzer.PropUpdate{
				Type: analyzer.PropUpdateMerge,
				M:    analyzer.PropMap{"resp": s.respMap},
			}
			s.respUpdated = false
		}
	} else {
		s.reqBuf.Append(data)
		s.reqUpdated = false
		cancelled, s.reqDone = s.reqLSM.Run()
		if s.reqUpdated {
			update = &analyzer.PropUpdate{
				Type: analyzer.PropUpdateMerge,
				M:    analyzer.PropMap{"req": s.reqMap},
			}
			s.reqUpdated = false
		}
	}
	return update, cancelled || (s.reqDone && s.respDone)
}

// ClientHello preprocess: same logic as TLS for handshake validation
func (s *quicStream) quicClientHelloPreprocess() utils.LSMAction {
	const headersSize = 4 // Type(1) + Len(3)
	const minDataSize = 41
	header, ok := s.reqBuf.Get(headersSize, true)
	if !ok {
		return utils.LSMActionPause
	}
	if header[0] != internal.TypeClientHello {
		return utils.LSMActionCancel
	}
	s.clientHelloLen = int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if s.clientHelloLen < minDataSize {
		return utils.LSMActionCancel
	}
	return utils.LSMActionNext
}

// ServerHello preprocess: same logic as TLS for handshake validation
func (s *quicStream) quicServerHelloPreprocess() utils.LSMAction {
	const headersSize = 4 // Type(1) + Len(3)
	const minDataSize = 38
	header, ok := s.respBuf.Get(headersSize, true)
	if !ok {
		return utils.LSMActionPause
	}
	if header[0] != internal.TypeServerHello {
		return utils.LSMActionCancel
	}
	s.serverHelloLen = int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if s.serverHelloLen < minDataSize {
		return utils.LSMActionCancel
	}
	return utils.LSMActionNext
}

func (s *quicStream) parseClientHelloData() utils.LSMAction {
	chBuf, ok := s.reqBuf.GetSubBuffer(s.clientHelloLen, true)
	if !ok {
		return utils.LSMActionPause
	}
	m := internal.ParseTLSClientHelloMsgData(chBuf)
	if m == nil {
		return utils.LSMActionCancel
	} else {
		s.reqUpdated = true
		s.reqMap = m
		return utils.LSMActionNext
	}
}

func (s *quicStream) parseServerHelloData() utils.LSMAction {
	shBuf, ok := s.respBuf.GetSubBuffer(s.serverHelloLen, true)
	if !ok {
		return utils.LSMActionPause
	}
	m := internal.ParseTLSServerHelloMsgData(shBuf)
	if m == nil {
		return utils.LSMActionCancel
	} else {
		s.respUpdated = true
		s.respMap = m
		return utils.LSMActionNext
	}
}

func (s *quicStream) Close(limited bool) *analyzer.PropUpdate {
	if s.reqBuf != nil {
		s.reqBuf.Reset()
	}
	if s.respBuf != nil {
		s.respBuf.Reset()
	}
	s.reqMap = nil
	s.respMap = nil
	return nil
}
