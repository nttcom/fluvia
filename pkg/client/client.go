// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package client

import (
	"net"
	"time"

	"github.com/nttcom/fluvia/pkg/ipfix"
)

func New(ingressIfName string, raddr *net.UDPAddr, interval int) ClientError {
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

	m := NewMeter(ingressIfName)
	go func() {
		err := m.Run(ch, time.Duration(interval))
		if err != nil {
			errChan <- ClientError{
				Component: "meter",
				Error:     err,
			}
		}
		m.Close()
	}()

	for {
		clientError := <-errChan
		return clientError
	}
}
