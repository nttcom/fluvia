// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package client

import (
	"net"

	"github.com/nttcom/fluvia/pkg/packet/ipfix"
)

func New(raddr *net.UDPAddr) ClientError {
	ch := make(chan ipfix.Set)
	errChan := make(chan ClientError)
	go NewExporter(raddr, ch, errChan)
	go NewDummyMeter(ch, errChan)
	for {
		serverError := <-errChan
		return serverError
	}
}
