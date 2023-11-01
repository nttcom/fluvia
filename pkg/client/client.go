// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package client

import (
	"net"
	"sync"

	"github.com/nttcom/fluvia/pkg/packet"
)

type Statistic struct {
	Count     int64
	DelayMean int64
	DelayMin  int64
	DelayMax  int64
	DelaySum  int64
}

type StatisticMap struct {
	Mu sync.Mutex
	Db map[packet.ProbeData]*Statistic
}

func New(ingressIfName string, raddr *net.UDPAddr) ClientError {
	sm := StatisticMap{Db: make(map[packet.ProbeData]*Statistic)}
	errChan := make(chan ClientError)

	e := NewExporter()
	go func() {
		err := e.Run(raddr, &sm)
		if err != nil {
			errChan <- ClientError{
				Component: "exporter",
				Error:     err,
			}
		}
	}()
	go NewMeter(ingressIfName, &sm)

	for {
		clientError := <-errChan
		return clientError
	}
}
