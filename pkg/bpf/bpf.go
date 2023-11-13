// Copyright (c) 2023 NTT Communications Corporation
// Copyright (c) 2023 Takeru Hayasaka
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package bpf

import (
	"errors"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc $BPF_CLANG -cflags $BPF_CFLAGS xdp ../../src/main.c -- -I../../src

type XdpMetaData struct {
	ReceivedNano uint64
	SentSec      uint32
	SentSubsec   uint32
}

type Xdp struct {
	objs *xdpObjects
	link link.Link
}

func ReadXdpObjects(ops *ebpf.CollectionOptions) (*Xdp, error) {
	obj := &xdpObjects{}
	err := loadXdpObjects(obj, ops)
	if err != nil {
		return nil, err
	}

	// TODO: BPF log level remove hardcoding. yaml in config
	if err != nil {
		return nil, err
	}

	return &Xdp{
		objs: obj,
	}, nil
}

func (x *Xdp) Attach(iface *net.Interface) error {
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   x.objs.XdpProg,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return err
	}

	x.link = l

	return nil
}

func (x *Xdp) NewPerfReader() (*perf.Reader, error) {
	return perf.NewReader(x.objs.PacketProbePerf, 4096)
}

func (x *Xdp) Close() error {
	errs := []error{}
	if err := x.objs.Close(); err != nil {
		errs = append(errs, err)
	}

	if err := x.link.Close(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

const (
	XDP_ABORTED uint32 = iota
	XDP_DROP
	XDP_PASS
	XDP_TX
	XDP_REDIRECT
)
