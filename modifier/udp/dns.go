package modifier

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// 只支持UDP，TCP流量不处理，直接返回原始数据
type DNSModifier struct{}

func (m *DNSModifier) Name() string {
	return "dns"
}

func (m *DNSModifier) New(args map[string]interface{}) (Instance, error) {
	i := &dnsModifierInstance{}
	i.seed = rand.Uint32()

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
				return nil, &ErrInvalidArgs{Err: errors.New("invalid ip list")}
			}
		case "file":
			if filePath, ok := value.(string); ok {
				if err := m.parseIpListFile(filePath, i); err != nil {
					return nil, err
				}
			} else {
				return nil, &ErrInvalidArgs{Err: errors.New("unable to open or parse ip list file")}
			}
		}
	}
	return i, nil
}

func (m *DNSModifier) parseIpEntry(entry interface{}, i *dnsModifierInstance) error {
	entryStr, ok := entry.(string)
	if !ok {
		return &ErrInvalidArgs{Err: errors.New("invalid ip")}
	}

	ip := net.ParseIP(entryStr)
	if ip == nil {
		return &ErrInvalidArgs{Err: fmt.Errorf("invalid ip: %s", entryStr)}
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
		return &ErrInvalidArgs{Err: fmt.Errorf("unable to open or parse ip list file: %s", filePath)}
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
		return &ErrInvalidArgs{Err: fmt.Errorf("unable to open or parse ip list file: %s", filePath)}
	}
	return nil
}

type dnsModifierInstance struct {
	A    []net.IP
	AAAA []net.IP
	seed uint32
}

// UDP实现
func (i *dnsModifierInstance) Process(data []byte) ([]byte, error) {
	dns := &layers.DNS{}
	err := dns.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, &ErrInvalidPacket{Err: err}
	}
	if !dns.QR || dns.ResponseCode != layers.DNSResponseCodeNoErr {
		return nil, &ErrInvalidPacket{Err: errors.New("not a valid dns response")}
	}
	if len(dns.Questions) == 0 {
		return nil, &ErrInvalidPacket{Err: errors.New("empty dns question")}
	}

	// Hash the query name so that DNS response is fixed for a given query.
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
			idx := hashStringToIndex(q.Name, len(i.A), i.seed)
			dns.Answers = []layers.DNSResourceRecord{{
				Name:  q.Name,
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    i.A[idx],
			}}
		}
	case layers.DNSTypeAAAA:
		if i.AAAA != nil {
			idx := hashStringToIndex(q.Name, len(i.AAAA), i.seed)
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

// TCP实现(原样返回，不处理)
func (i *dnsModifierInstance) ProcessTCP(data []byte, direction bool) ([]byte, error) {
	return data, nil
}

var _ Modifier = (*DNSModifier)(nil)
var _ UDPModifierInstance = (*dnsModifierInstance)(nil)
var _ TCPModifierInstance = (*dnsModifierInstance)(nil)
