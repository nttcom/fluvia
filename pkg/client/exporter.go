// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package client

import (
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/nttcom/fluvia/pkg/packet"
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

func (e *Exporter) Run(raddr *net.UDPAddr, sm *StatisticMap) error {
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	var m *ipfix.Message

	cache := make(map[packet.ProbeData]*Statistic)
	flowChan := make(chan []ipfix.FieldValue)

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			for probeData, stat := range sm.Db {
				if _, ok := cache[probeData]; !ok {
					cache[probeData] = &Statistic{
						Count:     0,
						DelayMean: 0,
						DelayMin:  0,
						DelayMax:  0,
						DelaySum:  0,
					}
				}

				dCnt := uint64(stat.Count - cache[probeData].Count)

				cache[probeData].Count = stat.Count

				sl := []ipfix.SRHSegmentIPv6{}
				for _, seg := range probeData.Segments {
					ipSeg, _ := netip.ParseAddr(seg)

					// Ignore zero values received from bpf map
					if ipSeg == netip.IPv6Unspecified() {
						break
					}
					seg := ipfix.SRHSegmentIPv6{Val: ipSeg}
					sl = append(sl, seg)
				}

				actSeg, _ := netip.ParseAddr(probeData.Segments[probeData.SegmentsLeft])

				f := []ipfix.FieldValue{
					&ipfix.PacketDeltaCount{Val: dCnt},
					&ipfix.SRHActiveSegmentIPv6{Val: actSeg},
					&ipfix.SRHSegmentsIPv6Left{Val: probeData.SegmentsLeft},
					&ipfix.SRHFlagsIPv6{Val: probeData.Flags},
					&ipfix.SRHTagIPv6{Val: probeData.Tag},
					&ipfix.SRHSegmentIPv6BasicList{
						SegmentList: sl,
					},
				}
				//  Throw to channel
				flowChan <- f
			}
		}
	}()

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
