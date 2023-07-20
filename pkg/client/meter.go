// Copyright (c) 2023 NTT Communications Corporation
// Copyright (c) 2023 Takeru Hayasaka
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package client

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/nttcom/fluvia/pkg/bpf"
	"github.com/nttcom/fluvia/pkg/packet/ipfix"
)

func NewMeter(ingressIfName string, ch chan []ipfix.FieldValue) {
	iface, err := net.InterfaceByName(ingressIfName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ingressIfName, err)
	}

	// Load the XDP program
	objs, err := bpf.ReadXdpObjects(nil)
	if err != nil {
		log.Fatalf("Could not load XDP program: %s", err)
	}
	defer objs.Close()

	// Attach the XDP program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	mapLogs := map[bpf.XdpProbeData]uint64{}
	for range ticker.C {
		var entry bpf.XdpProbeData
		var count uint64

		iter := objs.IpfixProbeMap.Iterate()

		for iter.Next(&entry, &count) {
			if _, ok := mapLogs[entry]; !ok {
				mapLogs[entry] = 0
			}

			dCnt := uint64(count - mapLogs[entry])

			mapLogs[entry] = count

			sl := []ipfix.SRHSegmentIPv6{}
			for _, binSeg := range entry.Segments {
				ipSeg, _ := netip.AddrFromSlice(binSeg.In6U.U6Addr8[:])

				// Ignore zero values received from bpf map
				if ipSeg == netip.IPv6Unspecified() {
					break
				}
				seg := ipfix.SRHSegmentIPv6{Val: ipSeg}
				sl = append(sl, seg)
			}

			actSeg, _ := netip.AddrFromSlice(entry.Segments[entry.SegmentsLeft].In6U.U6Addr8[:])

			f := []ipfix.FieldValue{
				&ipfix.PacketDeltaCount{Val: dCnt},
				&ipfix.SRHActiveSegmentIPv6{Val: actSeg},
				&ipfix.SRHSegmentsIPv6Left{Val: entry.SegmentsLeft},
				&ipfix.SRHFlagsIPv6{Val: entry.Flags},
				&ipfix.SRHTagIPv6{Val: entry.Tag},
				&ipfix.SRHSegmentIPv6BasicList{
					SegmentList: sl,
				},
			}
			//  Throw to channel
			ch <- f
		}
		if err := iter.Err(); err != nil {
			fmt.Printf("Failed to iterate map: %v\n", err)
		}
	}
}
