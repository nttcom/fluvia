package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nttcom/fluvia/internal/pkg/meter"
)

type testData struct {
	sentSec    uint32
	sentSubsec uint32
	probeData  meter.ProbeData
}

func generateInput(t *testing.T) []byte {
	t.Helper()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()

	srcIP := net.ParseIP("2001:db8::1")
	dstIP := net.ParseIP("2001:db8::2")
	srcMAC, _ := net.ParseMAC("02:42:ac:11:00:02")
	dstMAC, _ := net.ParseMAC("02:42:ac:11:00:03")
	srcPort := layers.UDPPort(12345)
	dstPort := layers.UDPPort(54321)

	// Define the SRv6 segment list
	segmentList := []netip.Addr{}

	addr, _ := netip.ParseAddr("2001:db8:dead:beef::1")
	segmentList = append(segmentList, addr)

	addr, _ = netip.ParseAddr("2001:db8:dead:beef::2")
	segmentList = append(segmentList, addr)

	// Create the Ethernet layer
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}

	// Create the IPv6 layer
	ipv6Layer := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6HopByHop,
		HopLimit:   64,
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}

	// Create the IPv6 Hop-By-Hop option layer
	hbhLayer := &meter.HBHLayer{
		NextHeader: uint8(layers.IPProtocolIPv6Routing),
		Length:     5,
		Options: []meter.IoamOption{
			{
				Type: meter.IPV6_TLV_PAD1,
			},
			{
				Type: meter.IPV6_TLV_PAD1,
			},
			{
				Type:       0x31,
				Length:     0x2a,
				Reserved:   0x00,
				OptionType: 0x00, // Pre-allocated Trace
				TraceHeader: meter.IoamTrace{
					NameSpaceId:  1,
					NodeLen:      4,
					Flags:        0b0000,
					RemainingLen: 0b0000001,
					Type:         [3]byte{0xf0, 0x00, 0x00},
					Reserved:     0x00,
					NodeDataList: []meter.NodeData{
						{
							HopLimitNodeId:   [4]byte{0x00, 0x00, 0x00, 0x00},
							IngressEgressIds: [4]byte{0x00, 0x00, 0x00, 0x00},
							Second:           [4]byte{0x00, 0x00, 0x00, 0x00},
							Subsecond:        [4]byte{0x00, 0x00, 0x00, 0x00},
						},
						{
							HopLimitNodeId:   [4]byte{0x40, 0x00, 0x00, 0x01},
							IngressEgressIds: [4]byte{0x00, 0x05, 0x00, 0x04},
							Second:           [4]byte{0x65, 0x38, 0xd5, 0xf6},
							Subsecond:        [4]byte{0x3b, 0x53, 0x3d, 0x00},
						},
					},
				},
			},
		},
	}

	// Create the SRv6 extension header layer
	seg6layer := &meter.Srv6Layer{
		NextHeader:   uint8(layers.IPProtocolUDP),
		HdrExtLen:    uint8((8+16*len(segmentList))/8 - 1),
		RoutingType:  4, // SRH
		SegmentsLeft: uint8(len(segmentList)),
		LastEntry:    uint8(len(segmentList) - 1),
		Flags:        0,
		Tag:          0,
		Segments:     segmentList,
	}
	// Create the UDP layer
	udpLayer := &layers.UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
	}
	if err := udpLayer.SetNetworkLayerForChecksum(ipv6Layer); err != nil {
		t.Fatal(err)
	}

	err := gopacket.SerializeLayers(buf, opts,
		ethernetLayer, ipv6Layer, hbhLayer, seg6layer, udpLayer,
		gopacket.Payload([]byte("Hello, SRv6!")),
	)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestXDPProg(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	objs := &xdpObjects{}
	err := loadXdpObjects(objs, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := objs.Close(); err != nil {
			t.Errorf("failed to close objs: %v", err)
		}
	}()

	fmt.Println("debug log")
	perfEvent, err := perf.NewReader(objs.PacketProbePerf, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := perfEvent.Close(); err != nil {
			t.Errorf("failed to close perfEvent: %v", err)
		}
	}()

	var metadata XdpMetaData

	expected := testData{
		sentSec:    0x6538d5f6,
		sentSubsec: 0x3b533d00,
		probeData: meter.ProbeData{
			H_source:     "02:42:ac:11:00:02",
			H_dest:       "02:42:ac:11:00:03",
			V6Srcaddr:    "2001:db8::1",
			V6Dstaddr:    "2001:db8::2",
			NextHdr:      uint8(layers.IPProtocolUDP),
			HdrExtLen:    uint8((8+16*2)/8 - 1),
			RoutingType:  4,
			SegmentsLeft: 2,
			LastEntry:    1,
			Flags:        0,
			Tag:          0,
			Segments: [10]string{
				"2001:db8:dead:beef::1",
				"2001:db8:dead:beef::2",
			},
		},
	}

	ret, _, err := objs.XdpProg.Test(generateInput(t))
	if err != nil {
		t.Error(err)
	}

	// retern code should be XDP_PASS
	if ret != 2 {
		t.Errorf("got %d want %d", ret, 2)
	}

	fmt.Println("before read")

	eventData, err := perfEvent.Read()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Done read")

	reader := bytes.NewReader(eventData.RawSample)

	if err := binary.Read(reader, binary.LittleEndian, &metadata); err != nil {
		t.Fatal(err)
	}

	metadataSize := unsafe.Sizeof(metadata)
	if len(eventData.RawSample) <= int(metadataSize) {
		t.Fatalf("XDP did not send raw packet")
	}

	probeData, err := meter.Parse(eventData.RawSample[metadataSize:])
	if err != nil {
		t.Fatal(err)
	}

	actual := testData{
		sentSec:    metadata.SentSec,
		sentSubsec: metadata.SentSubsec,
		probeData:  *probeData,
	}

	if actual != expected {
		t.Errorf("TEST FAILED\n")
		t.Errorf("expected value: %+v\n", expected)
		t.Errorf("actual   value: %+v\n", actual)
	}
}
