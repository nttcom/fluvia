package bpf

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

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
	segmentList := []net.IP{
		net.ParseIP("2001:db8:dead:beef::1"),
		net.ParseIP("2001:db8:dead:beef::2"),
	}

	// Create the Ethernet layer
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}

	// Create the IPv6 layer
	ipv6Layer := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Routing,
		HopLimit:   64,
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}

	// Create the SRv6 extension header layer
	seg6layer := &Srv6Layer{
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
		ethernetLayer, ipv6Layer, seg6layer, udpLayer,
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
	defer objs.Close()

	ret, _, err := objs.XdpProg.Test(generateInput(t))
	if err != nil {
		t.Error(err)
	}

	// retern code should be XDP_PASS
	if ret != 2 {
		t.Errorf("got %d want %d", ret, 2)
	}

	fmt.Println("debug log")
	var entry XdpProbeData
	var count uint64
	iter := objs.IpfixProbeMap.Iterate()
	for iter.Next(&entry, &count) {
		PrintEntrys(entry, count)
	}
	if err := iter.Err(); err != nil {
		fmt.Printf("Failed to iterate map: %v\n", err)
	}
}
