package udp

import (
	"bytes"
	"compress/gzip"
	"io"

	"github.com/pierrec/lz4/v4"
	"github.com/klauspost/compress/zstd"

	"github.com/v2TLS/XGFW/modifier"
)

type CompressModifier struct{}

func (m *CompressModifier) Name() string {
	return "compress"
}

func (m *CompressModifier) New(args map[string]interface{}) (modifier.Instance, error) {
	algo := "gzip"
	if v, ok := args["algo"].(string); ok {
		if v == "gzip" || v == "lz4" || v == "zstd" {
			algo = v
		}
	}
	mode := "compress"
	if v, ok := args["mode"].(string); ok {
		if v == "compress" || v == "decompress" {
			mode = v
		}
	}
	// 分别返回不同的实例
	if atype, ok := args["type"].(string); ok && atype == "tcp" {
		return &compressModifierTCPInstance{algo: algo, mode: mode}, nil
	}
	return &compressModifierUDPInstance{algo: algo, mode: mode}, nil
}

// UDP 实现
type compressModifierUDPInstance struct {
	algo string
	mode string
}

var _ modifier.UDPModifierInstance = (*compressModifierUDPInstance)(nil)

func (i *compressModifierUDPInstance) Process(data []byte) ([]byte, error) {
	return processCompress(i.algo, i.mode, data)
}

// TCP 实现
type compressModifierTCPInstance struct {
	algo string
	mode string
}

var _ modifier.TCPModifierInstance = (*compressModifierTCPInstance)(nil)

func (i *compressModifierTCPInstance) Process(data []byte, direction bool) ([]byte, error) {
	return processCompress(i.algo, i.mode, data)
}

// 公用逻辑
func processCompress(algo, mode string, data []byte) ([]byte, error) {
	switch algo {
	case "gzip":
		if mode == "compress" {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			_, err := gz.Write(data)
			if err != nil {
				return nil, &modifier.ErrInvalidPacket{Err: err}
			}
			if err := gz.Close(); err != nil {
				return nil, &modifier.ErrInvalidPacket{Err: err}
			}
			return buf.Bytes(), nil
		} else if mode == "decompress" {
			buf := bytes.NewReader(data)
			gz, err := gzip.NewReader(buf)
			if err != nil {
				return nil, &modifier.ErrInvalidPacket{Err: err}
			}
			defer gz.Close()
			out, err := io.ReadAll(gz)
			if err != nil {
				return nil, &modifier.ErrInvalidPacket{Err: err}
			}
			return out, nil
		}
	case "lz4":
		if mode == "compress" {
			var buf bytes.Buffer
			lz4w := lz4.NewWriter(&buf)
			_, err := lz4w.Write(data)
			if err != nil {
				return nil, &modifier.ErrInvalidPacket{Err: err}
			}
			if err := lz4w.Close(); err != nil {
				return nil, &modifier.ErrInvalidPacket{Err: err}
			}
			return buf.Bytes(), nil
		} else if mode == "decompress" {
			buf := bytes.NewReader(data)
			lz4r := lz4.NewReader(buf)
			out, err := io.ReadAll(lz4r)
			if err != nil {
				return nil, &modifier.ErrInvalidPacket{Err: err}
			}
			return out, nil
		}
	case "zstd":
		if mode == "compress" {
			var buf bytes.Buffer
			enc, err := zstd.NewWriter(&buf)
			if err != nil {
				return nil, &modifier.ErrInvalidPacket{Err: err}
			}
			_, err = enc.Write(data)
			if err != nil {
				enc.Close()
				return nil, &modifier.ErrInvalidPacket{Err: err}
			}
			if err := enc.Close(); err != nil {
				return nil, &modifier.ErrInvalidPacket{Err: err}
			}
			return buf.Bytes(), nil
		} else if mode == "decompress" {
			dec, err := zstd.NewReader(nil)
			if err != nil {
				return nil, &modifier.ErrInvalidPacket{Err: err}
			}
			defer dec.Close()
			out, err := dec.DecodeAll(data, nil)
			if err != nil {
				return nil, &modifier.ErrInvalidPacket{Err: err}
			}
			return out, nil
		}
	}
	return nil, &modifier.ErrInvalidArgs{Err: io.ErrUnexpectedEOF}
}
