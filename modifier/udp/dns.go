package udp

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"os"

	"github.com/v2TLS/XGFW/modifier"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type DNSModifier struct{}

func (m *DNSModifier) Name() string {
	return "dns"
}

func (m *DNSModifier) New(args map[string]interface{}) (modifier.Instance, error) {
	i := &dnsModifierUDPInstance{}
	i.Seed = rand.Uint32()

	for key, value := range args {
		switch key {
		case "a", "aaaa":
			if err := parseIpEntry(value, i); err != nil {
				return nil, err
			}
		case "list":
			if list, ok := value.([]interface{}); ok {
				if err := parseIpList(list, i); err != nil {
					return nil, err
				}
			} else {
				return nil, &modifier.ErrInvalidArgs{Err: errInvalidIPList}
			}
		case "file":
			if filePath, ok := value.(string); ok {
				if err := parseIpListFile(filePath, i); err != nil {
					return nil, err
				}
			} else {
				return nil, &modifier.ErrInvalidArgs{Err: errInvalidIpListFile}
			}
		}
	}
	return i, nil
}

var (
	errInvalidIP           = errors.New("invalid ip")
	errInvalidIPList       = errors.New("invalid ip list")
	errInvalidIpListFile   = errors.New("unable to open or parse ip list file")
	errNotValidDNSResponse = errors.New("not a valid dns response")
	errEmptyDNSQuestion    = errors.New("empty dns question")
)

func fmtErrInvalidIP(ip string) error {
	return fmt.Errorf("invalid ip: %s", ip)
}
func fmtErrInvalidIpListFile(filePath string) error {
	return fmt.Errorf("unable to open or parse ip list file: %s", filePath)
}

func parseIpEntry(entry interface{}, i *dnsModifierUDPInstance) error {
	entryStr, ok := entry.(string)
	if !ok {
		return &modifier.ErrInvalidArgs{Err: errInvalidIP}
	}
	ip := net.ParseIP(entryStr)
	if ip == nil {
		return &modifier.ErrInvalidArgs{Err: fmtErrInvalidIP(entryStr)}
	}
	if ip4 := ip.To4(); ip4 != nil {
		i.A = append(i.A, ip4)
	} else {
		i.AAAA = append(i.AAAA, ip)
	}
	return nil
}
func parseIpList(list []interface{}, i *dnsModifierUDPInstance) error {
	for _, entry := range list {
		if err := parseIpEntry(entry, i); err != nil {
			return err
		}
	}
	return nil
}
func parseIpListFile(filePath string, i *dnsModifierUDPInstance) error {
	file, err := os.Open(filePath)
	if err != nil {
		return &modifier.ErrInvalidArgs{Err: fmtErrInvalidIpListFile(filePath)}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if err := parseIpEntry(line, i); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return &modifier.ErrInvalidArgs{Err: fmtErrInvalidIpListFile(filePath)}
	}
	return nil
}

// UDP 实现
type dnsModifierUDPInstance struct {
	A    []net.IP
	AAAA []net.IP
	Seed uint32
}

var _ modifier.UDPModifierInstance = (*dnsModifierUDPInstance)(nil)

func (i *dnsModifierUDPInstance) Process(data []byte) ([]byte, error) {
	return processDNS(i.A, i.AAAA, i.Seed, data)
}

// TCP 实现
type dnsModifierTCPInstance struct {
	A    []net.IP
	AAAA []net.IP
	Seed uint32
}

var _ modifier.TCPModifierInstance = (*dnsModifierTCPInstance)(nil)

func (i *dnsModifierTCPInstance) Process(data []byte, direction bool) ([]byte, error) {
	return processDNS(i.A, i.AAAA, i.Seed, data)
}

// 公用逻辑
func processDNS(A []net.IP, AAAA []net.IP, seed uint32, data []byte) ([]byte, error) {
	dns := &layers.DNS{}
	err := dns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, &modifier.ErrInvalidPacket{Err: err}
	}
	if !dns.QR || dns.ResponseCode != layers.DNSResponseCodeNoErr {
		return nil, &modifier.ErrInvalidPacket{Err: errNotValidDNSResponse}
	}
	if len(dns.Questions) == 0 {
		return nil, &modifier.ErrInvalidPacket{Err: errEmptyDNSQuestion}
	}

	hashStringToIndex := func(b []byte, sliceLength int, seed uint32) int {
		h := fnv.New32a()
		seedBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(seedBytes, seed)
		h.Write(seedBytes)
		h.Write(b)
		hashValue := h.Sum32()
		return int(hashValue % uint32(sliceLength))
	}

	q := dns.Questions[0]
	switch q.Type {
	case layers.DNSTypeA:
		if A != nil {
			idx := hashStringToIndex(q.Name, len(A), seed)
			dns.Answers = []layers.DNSResourceRecord{{
				Name:  q.Name,
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    A[idx],
			}}
		}
	case layers.DNSTypeAAAA:
		if AAAA != nil {
			idx := hashStringToIndex(q.Name, len(AAAA), seed)
			dns.Answers = []layers.DNSResourceRecord{{
				Name:  q.Name,
				Type:  layers.DNSTypeAAAA,
				Class: layers.DNSClassIN,
				IP:    AAAA[idx],
			}}
		}
	}
	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, dns)
	return buf.Bytes(), err
}
