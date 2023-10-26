// Copyright (c) 2023 NTT Communications Corporation
// Copyright (c) 2023 Takeru Hayasaka
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package bpf

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc $BPF_CLANG -cflags $BPF_CFLAGS xdp ../../src/main.c -- -I../../src

type XdpProbeData struct {
	H_dest          [6]uint8
	H_source        [6]uint8
	H_proto         uint16
	_               [2]byte
	V6Srcaddr       struct{ In6U struct{ U6Addr8 [16]uint8 } }
	V6Dstaddr       struct{ In6U struct{ U6Addr8 [16]uint8 } }
	TstampSecond    uint32
	TstampSubsecond uint32
	NextHdr         uint8
	HdrExtLen       uint8
	RoutingType     uint8
	SegmentsLeft    uint8
	LastEntry       uint8
	Flags           uint8
	Tag             uint16
	Segments        [10]struct{ In6U struct{ U6Addr8 [16]uint8 } }
}

func ReadXdpObjects(ops *ebpf.CollectionOptions) (*xdpObjects, error) {
	obj := &xdpObjects{}
	err := loadXdpObjects(obj, ops)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// TODO: BPF log level remove hardcoding. yaml in config
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return obj, nil
}

const (
	XDP_ABORTED uint32 = iota
	XDP_DROP
	XDP_PASS
	XDP_TX
	XDP_REDIRECT
)

func PrintEntrys(entry XdpProbeData, count uint64) {
	mac := func(mac [6]uint8) string {
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	}
	saddr := net.IP(entry.V6Srcaddr.In6U.U6Addr8[:]).String()
	daddr := net.IP(entry.V6Dstaddr.In6U.U6Addr8[:]).String()

	unixTime := time.Unix(int64(entry.TstampSecond), int64(entry.TstampSubsecond))

	fmt.Printf(
		"H_dest: %s, H_source: %v, H_proto: %v, V6Dstaddr: %v, V6Srcaddr: %v Timestamp: %v(%v.%v) -> count: %v\n",
		mac(entry.H_dest), mac(entry.H_source), entry.H_proto, daddr, saddr, unixTime.Format(time.RFC3339Nano), entry.TstampSecond, entry.TstampSubsecond, count)

}
