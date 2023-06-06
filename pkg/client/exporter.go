// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package client

import (
	"log"
	"net"
	"os"

	"github.com/nttcom/fluvia/pkg/packet/ipfix"
)

const OBSERVATION_ID uint32 = 61166

func NewExporter(raddr *net.UDPAddr, setChan chan ipfix.Set, errChan chan ClientError) {
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		errChan <- ClientError{
			Component: "exporter",
			Error:     err,
		}
	}
	defer conn.Close()

	flowSeq := uint32(1)
	var m *ipfix.Message
	//get flow data from go channel
	for {
		s := <-setChan
		sets := []ipfix.Set{s}

		if s.SetID == ipfix.TEMPLATE_SETS_ID { // Template Sets
			m = ipfix.NewMessage(flowSeq, OBSERVATION_ID, sets)
		} else if s.SetID == ipfix.OPTIONS_TEMPLATE_SETS_ID { // Options Template Sets
			m = ipfix.NewMessage(flowSeq, OBSERVATION_ID, sets)
		} else if s.SetID >= 256 { // Data Sets
			m = ipfix.NewMessage(flowSeq, OBSERVATION_ID, sets)
			flowSeq += uint32(len(s.Records)) // mod 2^32
		}

		//prepare message data
		SendMessage(m, conn)
	}
}

func SendMessage(message *ipfix.Message, conn *net.UDPConn) {
	byteMessage := message.Serialize()

	_, err := conn.Write(byteMessage)
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}
}
