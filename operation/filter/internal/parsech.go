package internal

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// parseTLSClientHelloFromTCP 尝试从原始 TCP 数据流中解析 TLS ClientHello 并提取关键信息。
// 返回值 map 兼容 internal.ParseTLSClientHelloMsgData 格式：
//  - CipherSuites []interface{}
//  - SupportedGroups []interface{}
//  - ALPNs []interface{}
//  - Certificate/PeerCertificates []string (PEM)
//  - SNI string
func parseTLSClientHelloFromTCP(buf []byte) map[string]interface{} {
	// TLS record header: 5 bytes
	// [0] ContentType (0x16=Handshake)
	// [1-2] Version
	// [3-4] Length
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
	// Parse ClientHello
	out := make(map[string]interface{})
	cur := 4 // skip HandshakeType(1)+length(3)
	if cur+2 > len(handshake) {
		return nil
	}
	// client_version := handshake[cur:cur+2]
	cur += 2
	// Random (32)
	cur += 32
	if cur >= len(handshake) {
		return nil
	}
	// Session ID
	sidLen := int(handshake[cur])
	cur++
	cur += sidLen
	if cur+2 > len(handshake) {
		return nil
	}
	// Cipher Suites
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
	// Compression methods
	compLen := int(handshake[cur])
	cur++
	cur += compLen
	if cur+2 > len(handshake) {
		return nil
	}
	// Extensions
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
		extLen := int(binary.BigEndian.Uint16(extData[extCur+2 : extCur+4]))
		extCur += 4
		if extCur+extLen > len(extData) {
			break
		}
		extVal := extData[extCur : extCur+extLen]

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
		extCur += extLen
	}
	out["ALPNs"] = alpnList
	out["SupportedGroups"] = groups
	if sni != "" {
		out["SNI"] = strings.ToLower(sni)
	}
	// 证书提取不在ClientHello中，留空
	return out
}
