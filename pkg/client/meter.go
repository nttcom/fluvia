// Copyright (c) 2023 NTT Communications Corporation
// Copyright (c) 2023 Takeru Hayasaka
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/nttcom/fluvia/pkg/bpf"
	"github.com/nttcom/fluvia/pkg/packet"
)

func NewMeter(ingressIfName string, sm *StatisticMap) {
	bootTime, err := getSystemBootTime()
	if err != nil {
		log.Fatalf("Could not get boot time: %s", err)
	}

	iface, err := net.InterfaceByName(ingressIfName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ingressIfName, err)
	}

	// Load the XDP program
	objs, err := bpf.ReadXdpObjects(&ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  ebpf.DefaultVerifierLogSize * 256,
		},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Could not load XDP program: %+v\n", ve)
		}
	}
	defer objs.Close()

	// Attach the XDP program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Could not attach XDP program: %s", err)
	}
	defer l.Close()

	perfEvent, err := perf.NewReader(objs.PacketProbePerf, 4096)
	if err != nil {
		log.Fatalf("Could not obtain perf reader: %s", err)
	}

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	var metadata bpf.XdpMetaData
	for {
		eventData, err := perfEvent.Read()
		if err != nil {
			log.Fatalf("Could not read from bpf perf map:")
		}

		reader := bytes.NewReader(eventData.RawSample)

		if err := binary.Read(reader, binary.LittleEndian, &metadata); err != nil {
			log.Fatalf("Could not read from reader: %s", err)
		}

		metadata_size := unsafe.Sizeof(metadata)
		if len(eventData.RawSample)-int(metadata_size) <= 0 {
			continue
		}

		receivedNano := bootTime.Add(time.Duration(metadata.ReceivedNano) * time.Nanosecond)
		SentNano := time.Unix(int64(metadata.SentSec), int64(metadata.SentSubsec))

		delay := receivedNano.Sub(SentNano)

		probeData, err := packet.Parse(eventData.RawSample[metadata_size:])
		if err != nil {
			log.Fatalf("Could not parse the packet: %s", err)
		}

		delayNano := delay.Nanoseconds()

		sm.Mu.Lock()
		if value, ok := sm.Db[*probeData]; !ok {
			sm.Db[*probeData] = &Statistic{
				Count:     1,
				DelayMean: delayNano,
				DelayMin:  delayNano,
				DelayMax:  delayNano,
				DelaySum:  delayNano,
			}
		} else {
			value.Count = value.Count + 1

			if delayNano < value.DelayMin {
				value.DelayMin = delayNano
			}

			if delayNano > value.DelayMax {
				value.DelayMax = delayNano
			}

			value.DelaySum = value.DelaySum + delayNano
			value.DelayMean = value.DelaySum / value.Count
		}
		sm.Mu.Unlock()
	}
}

func getSystemBootTime() (time.Time, error) {
	data, err := ioutil.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}, err
	}

	parts := strings.Split(string(data), " ")
	if len(parts) == 0 {
		return time.Time{}, fmt.Errorf("unexpected /proc/uptime format")
	}

	uptime, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return time.Time{}, err
	}

	return time.Now().Add(-time.Duration(uptime) * time.Second), nil
}
