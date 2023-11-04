// Copyright (c) 2023 NTT Communications Corporation
// Copyright (c) 2023 Takeru Hayasaka
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/nttcom/fluvia/internal/pkg/meter"
	"github.com/nttcom/fluvia/pkg/bpf"
	"github.com/nttcom/fluvia/pkg/ipfix"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

type Stats struct {
	Count     int64
	DelayMean int64
	DelayMin  int64
	DelayMax  int64
	DelaySum  int64
}

type StatsMap struct {
	Mu sync.RWMutex
	Db map[meter.ProbeData]*Stats
}

type Meter struct {
	statsMap *StatsMap
	bootTime time.Time
	xdp      *bpf.Xdp
}

func NewMeter(ingressIfName string) *Meter {
	bootTime, err := getSystemBootTime()
	if err != nil {
		log.Fatalf("Could not get boot time: %s", err)
	}

	statsMap := StatsMap{Db: make(map[meter.ProbeData]*Stats)}

	iface, err := net.InterfaceByName(ingressIfName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ingressIfName, err)
	}

	// Load the XDP program
	xdp, err := bpf.ReadXdpObjects(&ebpf.CollectionOptions{
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

	// Attach the XDP program.
	if err = xdp.Attach(iface); err != nil {
		log.Fatalf("Could not attach XDP program: %s", err)
	}

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	return &Meter{
		statsMap: &statsMap,
		bootTime: bootTime,
		xdp:      xdp,
	}
}

func (m *Meter) Run(flowChan chan []ipfix.FieldValue, interval time.Duration) error {
	eg, ctx := errgroup.WithContext(context.Background())
	eg.Go(func() error {
		return m.Read(ctx)
	})
	eg.Go(func() error {
		return m.Send(ctx, flowChan, interval)
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}

func (m *Meter) Read(ctx context.Context) error {
	perfEvent, err := m.xdp.NewPerfReader()
	if err != nil {
		log.Fatalf("Could not obtain perf reader: %s", err)
	}

	var metadata bpf.XdpMetaData
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
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

			receivedNano := m.bootTime.Add(time.Duration(metadata.ReceivedNano) * time.Nanosecond)
			SentNano := time.Unix(int64(metadata.SentSec), int64(metadata.SentSubsec))

			delay := receivedNano.Sub(SentNano)

			probeData, err := meter.Parse(eventData.RawSample[metadata_size:])
			if err != nil {
				log.Fatalf("Could not parse the packet: %s", err)
			}

			delayMicro := delay.Microseconds()

			m.statsMap.Mu.Lock()
			if value, ok := m.statsMap.Db[*probeData]; !ok {
				m.statsMap.Db[*probeData] = &Stats{
					Count:     1,
					DelayMean: delayMicro,
					DelayMin:  delayMicro,
					DelayMax:  delayMicro,
					DelaySum:  delayMicro,
				}
			} else {
				value.Count = value.Count + 1

				if delayMicro < value.DelayMin {
					value.DelayMin = delayMicro
				}

				if delayMicro > value.DelayMax {
					value.DelayMax = delayMicro
				}

				value.DelaySum = value.DelaySum + delayMicro
				value.DelayMean = value.DelaySum / value.Count
			}
			m.statsMap.Mu.Unlock()
		}
	}
}

func (m *Meter) Send(ctx context.Context, flowChan chan []ipfix.FieldValue, intervalSec time.Duration) error {
	ticker := time.NewTicker(intervalSec * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		select {
		case <-ctx.Done():
			return nil
		default:
			m.statsMap.Mu.Lock()
			for probeData, stat := range m.statsMap.Db {
				dCnt := uint64(stat.Count)

				sl := []ipfix.SRHSegmentIPv6{}
				for _, seg := range probeData.Segments {
					if seg == "" {
						break
					}
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
					&ipfix.PathDelayMeanDeltaMicroseconds{Val: uint32(stat.DelayMean)},
					&ipfix.PathDelayMinDeltaMicroseconds{Val: uint32(stat.DelayMin)},
					&ipfix.PathDelayMaxDeltaMicroseconds{Val: uint32(stat.DelayMax)},
					&ipfix.PathDelaySumDeltaMicroseconds{Val: uint32(stat.DelaySum)},
				}
				//  Throw to channel
				flowChan <- f

				// Stats (e.g., DelayMean) are based on packets received over a fixed duration
				// These need to be cleared out for the next calculation of statistics
				delete(m.statsMap.Db, probeData)
			}
			m.statsMap.Mu.Unlock()
		}
	}

	return nil
}

func (m *Meter) Close() error {
	if err := m.xdp.Close(); err != nil {
		return err
	}

	return nil
}

func getSystemBootTime() (time.Time, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return time.Time{}, err
	}
	return time.Now().Add(-time.Duration(ts.Nano())), nil
}
