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

// 支持三种算法：gzip, lz4, zstd，模式：compress 或 decompress
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
	return &compressModifierInstance{algo: algo, mode: mode}, nil
}

type compressModifierInstance struct {
	algo string // "gzip", "lz4", "zstd"
	mode string // "compress", "decompress"
}

// UDP接口实现
func (i *compressModifierInstance) Process(data []byte) ([]byte, error) {
	return i.processCommon(data)
}

// TCP接口实现
func (i *compressModifierInstance) ProcessTCP(data []byte, direction bool) ([]byte, error) {
	return i.processCommon(data)
}

// 满足接口要求
var _ modifier.Modifier = (*CompressModifier)(nil)
var _ modifier.UDPModifierInstance = (*compressModifierInstance)(nil)
var _ modifier.TCPModifierInstance = (*compressModifierInstance)(nil)

func (i *compressModifierInstance) processCommon(data []byte) ([]byte, error) {
	switch i.algo {
	case "gzip":
		if i.mode == "compress" {
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
		} else if i.mode == "decompress" {
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
		if i.mode == "compress" {
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
		} else if i.mode == "decompress" {
			buf := bytes.NewReader(data)
			lz4r := lz4.NewReader(buf)
			out, err := io.ReadAll(lz4r)
			if err != nil {
				return nil, &modifier.ErrInvalidPacket{Err: err}
			}
			return out, nil
		}
	case "zstd":
		if i.mode == "compress" {
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
		} else if i.mode == "decompress" {
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
