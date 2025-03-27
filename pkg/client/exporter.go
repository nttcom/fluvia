// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package client

import (
	"log"
	"net"
	"os"

	"github.com/nttcom/fluvia/pkg/ipfix"
)

const OBSERVATION_ID uint32 = 61166

type Exporter struct {
	flowSeq    uint32
	tempRecSeq uint16
}

func NewExporter() *Exporter {
	e := &Exporter{
		flowSeq:    1,
		tempRecSeq: 256,
	}
	return e
}

func (e *Exporter) Run(raddr *net.UDPAddr, flowChan chan []ipfix.FieldValue) error {
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("failed to close connection: %v", err)
		}
	}()

	var m *ipfix.Message
	// get flow data from go channel
	for {
		fvs := <-flowChan
		var sets []ipfix.Set
		// 1. Create template data set
		var fss []ipfix.FieldSpecifier
		for _, fv := range fvs {
			fss = append(fss, *fv.FieldSpecifier())
		}
		tempRec := ipfix.NewTemplateRecord(e.tempRecSeq, fss)
		tempSet := ipfix.NewSet(ipfix.TEMPLATE_SETS_ID, []ipfix.Record{tempRec})
		sets = append(sets, *tempSet)

		// 2. Create data set
		dataRec := &ipfix.DataRecord{FieldValues: fvs}
		dataSet := ipfix.NewSet(e.tempRecSeq, []ipfix.Record{dataRec})
		sets = append(sets, *dataSet)

		// 3. Create Message and Increment Sequence
		m = ipfix.NewMessage(e.flowSeq, OBSERVATION_ID, sets)
		e.tempRecSeq += uint16(len(tempSet.Records))
		e.flowSeq += uint32(len(dataSet.Records))

		//4. Send message data
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
