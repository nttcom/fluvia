package meter

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const IPV6_TLV_PAD1 = 0

type HBHLayer struct {
    layers.BaseLayer
    NextHeader uint8
    Length uint8
    Options []IoamOption
}

type IoamOption struct {
    Type uint8
    Length uint8
    Reserved uint8
    OptionType uint8
    TraceHeader IoamTrace
}

type IoamTrace struct {
    NameSpaceId uint16
    NodeLen  uint8
    Flags       byte
    RemainingLen uint8
    Type     [3]byte
    Reserved byte
    NodeDataList []NodeData
}

type NodeData struct {
    HopLimitNodeId [4]byte
    IngressEgressIds [4]byte
    Second [4]byte
    Subsecond [4]byte
}

var HBHLayerType = gopacket.RegisterLayerType(
    2002,
    gopacket.LayerTypeMetadata{
        Name: "HBHLayerType",
        Decoder: gopacket.DecodeFunc(decodeHBHLayer),
    },
)

func (l *HBHLayer) LayerType() gopacket.LayerType {
    return HBHLayerType
}

func (l *HBHLayer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    p := 0

    // Min length of each header
    // HBHLayer = 2, IoamOption = 3, IoamTrae = 8
    if len(data) < 2 + 3 + 8 {
        df.SetTruncated()
        return errors.New("HBH layer less than 2 bytes for HBH packet")
    }

    l.NextHeader = data[p]; p++
    l.Length = data[p]; p++

    optionIdx := 0
    for {
        if data[p] != IPV6_TLV_PAD1 {
            break
        }

        l.Options[optionIdx].Type = IPV6_TLV_PAD1
        optionIdx = optionIdx + 1
        p = p + 1
    }

    ioamOption := l.Options[optionIdx]

    ioamOption.Type = data[p]; p++
    ioamOption.Length = data[p]; p++
    ioamOption.Reserved = data[p]; p++
    ioamOption.OptionType = data[p]; p++

    trace := ioamOption.TraceHeader
    trace.NameSpaceId = binary.BigEndian.Uint16(data[p:p+2])
    p = p + 2
    trace.NodeLen = data[p] >> 3;
    trace.Flags = ((data[p] & 0b00000111) << 1) | (data[p+1] >> 7)
    p = p + 1
    trace.RemainingLen = data[p] & 0b01111111
    p = p + 1
    copy(trace.Type[:], data[p:p+3])
    p = p + 3
    trace.Reserved = data[p]; p++

    traceDataLen := ioamOption.Length - (2 + 8)
    for i := 0; i < int(traceDataLen) / 4 / int(trace.NodeLen); i++ {
        var (
            hopLimitNodeId [4]byte
            ingressEgressIds [4]byte
            second [4]byte
            subsecond [4]byte
        )

        copy(hopLimitNodeId[:], data[p+16*i:p+16*i+4])
        copy(ingressEgressIds[:], data[p+16*i+4:p+16*i+8])
        copy(second[:], data[p+16*i+8:p+16*i+12])
        copy(subsecond[:], data[p+16*i+12:p+16*i+16])

        nodeData := NodeData{
            HopLimitNodeId: hopLimitNodeId,
            IngressEgressIds: ingressEgressIds,
            Second: second,
            Subsecond: subsecond,
        }

        trace.NodeDataList = append(trace.NodeDataList, nodeData)
    }

    return nil
}

func (l *HBHLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
    length := l.Length * 8 + 8
    bytes, err := b.PrependBytes(int(length))
    if err != nil {
        return err
    }

    p := 0

    bytes[p] = l.NextHeader; p++
    bytes[p] = l.Length; p++

    optionIdx := 0
    for i, option := range l.Options {
        if option.Type != IPV6_TLV_PAD1 {
            optionIdx = i
            break
        }

        bytes[p] = IPV6_TLV_PAD1; p++
    }

    ioamOption := l.Options[optionIdx]
    bytes[p] = ioamOption.Type; p++
    bytes[p] = ioamOption.Length; p++
    bytes[p] = ioamOption.Reserved; p++
    bytes[p] = ioamOption.OptionType; p++

    traceOption := ioamOption.TraceHeader
    binary.BigEndian.PutUint16(bytes[p:], traceOption.NameSpaceId)
    p = p + 2
    bytes[p] = traceOption.NodeLen << 3;
    bytes[p] = (bytes[p] & 0xf8) | ((traceOption.Flags >> 1) & 0x07)
    p++
    bytes[p] = (traceOption.Flags & 0x01) << 7
    bytes[p] = (bytes[p] & 0x80) | (traceOption.RemainingLen & 0x7f)
    p++
    copy(bytes[p:p+3], traceOption.Type[:])
    p = p + 3
    bytes[p] = traceOption.Reserved; p++

    traceDataLen := ioamOption.Length - (2 + 8)
    for i := 0; i < int(traceDataLen) / 4 / int(traceOption.NodeLen); i++ {
        nodeData := traceOption.NodeDataList[i]
        copy(bytes[p+16*i:p+16*i+4], nodeData.HopLimitNodeId[:])
        copy(bytes[p+16*i+4:p+16*i+8], nodeData.IngressEgressIds[:])
        copy(bytes[p+16*i+8:p+16*i+12], nodeData.Second[:])
        copy(bytes[p+16*i+12:p+16*i+16], nodeData.Subsecond[:])
    }

    return nil
}

func (l *HBHLayer) NextLayerType() gopacket.LayerType {
        return gopacket.LayerTypePayload
}

func decodeHBHLayer(data []byte, p gopacket.PacketBuilder) error {
    l := &HBHLayer{}
    err := l.DecodeFromBytes(data, p)
    if err != nil {
        return nil
    }
    p.AddLayer(l)
    next := l.NextLayerType()
    if next == gopacket.LayerTypeZero {
        return nil
    }

    return p.NextDecoder(next)
}
