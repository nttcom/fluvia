// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package main

import (
	"log"
	"net"
	"net/netip"

	"github.com/nttcom/fluvia/pkg/client"
	"github.com/nttcom/fluvia/pkg/packet/ipfix"
)

func main() {
	flowChan := make(chan []ipfix.FieldValue)
	raddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:4739")
	if err != nil {
		log.Panic(err)
	}
	e := client.NewExporter()
	go func() {
		err := e.Run(raddr, flowChan)
		if err != nil {
			log.Panic(err)
		}
	}()

	appx1_1 := []ipfix.FieldValue{
		&ipfix.SRHFlagsIPv6{Val: 0xaa},
		&ipfix.SRHTagIPv6{Val: 0xaaaa},
		&ipfix.SRHIPv6ActiveSegmentType{Val: 0x04},
		&ipfix.SRHSegmentIPv6BasicList{
			SegmentList: []ipfix.SRHSegmentIPv6{
				{Val: netip.MustParseAddr("2001:db8::1")},
				{Val: netip.MustParseAddr("2001:db8::2")},
				{Val: netip.MustParseAddr("2001:db8::3")},
			},
		},
	}

	flowChan <- appx1_1

	appx1_2 := []ipfix.FieldValue{
		&ipfix.SRHFlagsIPv6{Val: 0xaa},
		&ipfix.SRHTagIPv6{Val: 0xaaaa},
		&ipfix.SRHIPv6ActiveSegmentType{Val: 0x04},
		&ipfix.SRHSegmentIPv6ListSection{
			SegmentList: []netip.Addr{
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("2001:db8::2"),
				netip.MustParseAddr("2001:db8::3"),
			},
		},
	}

	flowChan <- appx1_2
}
