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
	ch := make(chan []ipfix.FieldValue)
	errChan := make(chan ClientError)

	e := NewExporter()
	go func() {
		err := e.Run(raddr, ch)
		if err != nil {
			errChan <- ClientError{
				Component: "exporter",
				Error:     err,
			}
		}
	}()

	for {
		clientError := <-errChan
		return clientError
	}
}
