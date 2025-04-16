package tcp

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/v2TLS/XGFW/operation/protocol"
)

// mockLogger implements analyzer.Logger for testing
type mockLogger struct {
	msgs []string
}

func (l *mockLogger) Debugf(format string, args ...interface{}) {}
func (l *mockLogger) Infof(format string, args ...interface{})  {}
func (l *mockLogger) Errorf(format string, args ...interface{}) {}

func makeTCPInfo(ip string) protocol.TCPInfo {
	return protocol.TCPInfo{
		SrcIP:   net.ParseIP("1.2.3.4"),
		DstIP:   net.ParseIP(ip),
		SrcPort: 12345,
		DstPort: 443,
	}
}

func Test_XTLSAnalyzer_Alert(t *testing.T) {
	a := &XTLSAnalyzer{}
	logger := &mockLogger{}
	info := makeTCPInfo("8.8.8.8")

	stream := a.NewTCP(info, logger)

	// Craft a TLS alert record: ContentType=21, Version=3,3, Length=30 (not 26)
	data := make([]byte, 7)
	data[0] = 21        // ContentType: Alert
	data[1] = 3         // Version major
	data[2] = 3         // Version minor
	binary.BigEndian.PutUint16(data[3:5], 30) // Length != 26 (should trigger)
	data[5] = 1
	data[6] = 2

	update, done := stream.Feed(false, true, false, 0, data)
	if !done || update == nil || update.M["block"] != true {
		t.Errorf("expected block on forbidden alert, got: %+v, done=%v", update, done)
	}
}

func Test_XTLSAnalyzer_TLS12NonceSeq(t *testing.T) {
	a := &XTLSAnalyzer{}
	logger := &mockLogger{}
	info := makeTCPInfo("8.8.4.4")

	stream := a.NewTCP(info, logger)

	// Craft a TLS 1.2 AEAD record: ContentType=23, Version=3,3, Length=16, Nonce sequence=123456789
	data := make([]byte, 16)
	data[0] = 23        // ContentType: Application Data
	data[1] = 3         // Version major
	data[2] = 3         // Version minor
	binary.BigEndian.PutUint16(data[3:5], 8)
	binary.BigEndian.PutUint64(data[5:13], 123456789)
	// rest is padding

	update, done := stream.Feed(false, true, false, 0, data)
	if !done || update == nil || update.M["block"] != true {
		t.Errorf("expected block on TLS 1.2 nonce sequence, got: %+v, done=%v", update, done)
	}
}

func Test_XTLSAnalyzer_NormalTraffic(t *testing.T) {
	a := &XTLSAnalyzer{}
	logger := &mockLogger{}
	info := makeTCPInfo("1.1.1.1")

	stream := a.NewTCP(info, logger)

	// Normal TLS 1.3 Application Data (should not block)
	// ContentType=23, Version=3,3, Length=16, but Nonce sequence=0 (not detected)
	data := make([]byte, 16)
	data[0] = 23
	data[1] = 3
	data[2] = 3
	binary.BigEndian.PutUint16(data[3:5], 8)
	// Nonce sequence = 0 (no detection)
	for i := 5; i < 13; i++ {
		data[i] = 0
	}

	update, done := stream.Feed(false, true, false, 0, data)
	if done || update != nil {
		t.Errorf("expected not block on normal traffic, got: %+v, done=%v", update, done)
	}
}

// Optional: Test repeated Feed after block (should remain blocked)
func Test_XTLSAnalyzer_RepeatedFeed(t *testing.T) {
	a := &XTLSAnalyzer{}
	logger := &mockLogger{}
	info := makeTCPInfo("9.9.9.9")

	stream := a.NewTCP(info, logger)

	// Block on forbidden alert first
	data := make([]byte, 7)
	data[0] = 21
	data[1] = 3
	data[2] = 3
	binary.BigEndian.PutUint16(data[3:5], 30)
	data[5] = 1
	data[6] = 2

	update, done := stream.Feed(false, true, false, 0, data)
	if !done || update == nil || update.M["block"] != true {
		t.Errorf("expected block on forbidden alert, got: %+v, done=%v", update, done)
	}

	// Feed again, should be ignored (done)
	update, done = stream.Feed(false, false, false, 0, data)
	if !done || update != nil {
		t.Errorf("expected no update after done, got: %+v, done=%v", update, done)
	}
}

// Optional: Test empty or skipped data
func Test_XTLSAnalyzer_EmptyOrSkipped(t *testing.T) {
	a := &XTLSAnalyzer{}
	logger := &mockLogger{}
	info := makeTCPInfo("7.7.7.7")
	stream := a.NewTCP(info, logger)

	update, done := stream.Feed(false, false, false, 1, nil)
	if !done || update != nil {
		t.Errorf("expected done on skip, got: %+v, done=%v", update, done)
	}
	update, done = stream.Feed(false, false, false, 0, nil)
	if done || update != nil {
		t.Errorf("expected not done on empty data, got: %+v, done=%v", update, done)
	}
}

// Optional: Test stats file writing (optional, may require mock FS)
func Test_XTLSAnalyzer_Stats(t *testing.T) {
	_ = xtlsUpdateStats("6.6.6.6", "forbidden_alert")
	_ = xtlsUpdateStats("6.6.6.6", "tls12_nonce_sequence")
}
