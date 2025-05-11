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

var _ modifier.Modifier = (*DNSModifier)(nil)
var _ modifier.UDPModifierInstance = (*dnsModifierInstance)(nil)
var _ modifier.TCPModifierInstance = (*dnsModifierInstance)(nil)

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

type DNSModifier struct{}

func (m *DNSModifier) Name() string {
	return "dns"
}

func (m *DNSModifier) parseIpEntry(entry interface{}, i *dnsModifierInstance) error {
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

func (m *DNSModifier) parseIpList(list []interface{}, i *dnsModifierInstance) error {
	for _, entry := range list {
		if err := m.parseIpEntry(entry, i); err != nil {
			return err
		}
	}
	return nil
}

func (m *DNSModifier) parseIpListFile(filePath string, i *dnsModifierInstance) error {
	file, err := os.Open(filePath)
	if err != nil {
		return &modifier.ErrInvalidArgs{Err: fmtErrInvalidIpListFile(filePath)}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if err := m.parseIpEntry(line, i); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return &modifier.ErrInvalidArgs{Err: fmtErrInvalidIpListFile(filePath)}
	}

	return nil
}

func (m *DNSModifier) New(args map[string]interface{}) (modifier.Instance, error) {
	i := &dnsModifierInstance{}
	i.Seed = rand.Uint32()

	for key, value := range args {
		switch key {
		case "a", "aaaa":
			if err := m.parseIpEntry(value, i); err != nil {
				return nil, err
			}
		case "list":
			if list, ok := value.([]interface{}); ok {
				if err := m.parseIpList(list, i); err != nil {
					return nil, err
				}
			} else {
				return nil, &modifier.ErrInvalidArgs{Err: errInvalidIPList}
			}
		case "file":
			if filePath, ok := value.(string); ok {
				if err := m.parseIpListFile(filePath, i); err != nil {
					return nil, err
				}
			} else {
				return nil, &modifier.ErrInvalidArgs{Err: errInvalidIpListFile}
			}
		}
	}
	return i, nil
}

type dnsModifierInstance struct {
	A    []net.IP
	AAAA []net.IP
	Seed uint32
}

// UDP实现
func (i *dnsModifierInstance) Process(data []byte) ([]byte, error) {
	return i.processDNS(data)
}

// TCP实现（完全复用UDP逻辑，实际场景很少，但为接口一致性而实现）
func (i *dnsModifierInstance) ProcessTCP(data []byte, direction bool) ([]byte, error) {
	return i.processDNS(data)
}

func (i *dnsModifierInstance) processDNS(data []byte) ([]byte, error) {
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
		if i.A != nil {
			idx := hashStringToIndex(q.Name, len(i.A), i.Seed)
			dns.Answers = []layers.DNSResourceRecord{{
				Name:  q.Name,
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    i.A[idx],
			}}
		}
	case layers.DNSTypeAAAA:
		if i.AAAA != nil {
			idx := hashStringToIndex(q.Name, len(i.AAAA), i.Seed)
			dns.Answers = []layers.DNSResourceRecord{{
				Name:  q.Name,
				Type:  layers.DNSTypeAAAA,
				Class: layers.DNSClassIN,
				IP:    i.AAAA[idx],
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
