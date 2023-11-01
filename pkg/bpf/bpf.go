// Copyright (c) 2023 NTT Communications Corporation
// Copyright (c) 2023 Takeru Hayasaka
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc $BPF_CLANG -cflags $BPF_CFLAGS xdp ../../src/main.c -- -I../../src

type XdpMetaData struct {
	ReceivedNano uint64
	SentSec      uint32
	SentSubsec   uint32
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
