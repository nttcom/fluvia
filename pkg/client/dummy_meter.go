// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package client

import (
	"time"

	"github.com/nttcom/fluvia/pkg/packet/ipfix"
)

func NewDummyMeter(setChan chan ipfix.Set, errChan chan ClientError) {
	templateSet := ipfix.Set{
		SetID: uint16(2), // Template Set = Data Template
		Records: []ipfix.Record{
			&ipfix.TemplateRecord{
				TemplateID: uint16(256), // specifies DataSet
				FieldSpecifiers: []ipfix.FieldSpecifier{
					{
						E:                    bool(true),
						InformationElementID: uint16(500),
						FieldLength:          uint16(1),
						EnterpriseNumber:     uint32(29319),
					},
					{
						E:                    bool(true),
						InformationElementID: uint16(501),
						FieldLength:          uint16(2),
						EnterpriseNumber:     uint32(29319),
					},
					{
						E:                    bool(true),
						InformationElementID: uint16(508),
						FieldLength:          uint16(1),
						EnterpriseNumber:     uint32(29319),
					},
					{
						E:                    bool(true),
						InformationElementID: uint16(504),
						FieldLength:          uint16(0xffff),
						EnterpriseNumber:     uint32(29319),
					},
					{
						E:                    bool(true),
						InformationElementID: uint16(521),
						FieldLength:          uint16(2),
						EnterpriseNumber:     uint32(29319),
					},
					{
						E:                    bool(true),
						InformationElementID: uint16(522),
						FieldLength:          uint16(4),
						EnterpriseNumber:     uint32(29319),
					},
					{
						E:                    bool(true),
						InformationElementID: uint16(523),
						FieldLength:          uint16(2),
						EnterpriseNumber:     uint32(29319),
					},
					{
						E:                    bool(true),
						InformationElementID: uint16(524),
						FieldLength:          uint16(4),
						EnterpriseNumber:     uint32(29319),
					},
					{
						E:                    bool(true),
						InformationElementID: uint16(525),
						FieldLength:          uint16(2),
						EnterpriseNumber:     uint32(29319),
					},
					{
						E:                    bool(true),
						InformationElementID: uint16(526),
						FieldLength:          uint16(4),
						EnterpriseNumber:     uint32(29319),
					},
					{
						E:                    bool(true),
						InformationElementID: uint16(527),
						FieldLength:          uint16(4),
						EnterpriseNumber:     uint32(29319),
					},
					{
						E:                    bool(true),
						InformationElementID: uint16(528),
						FieldLength:          uint16(8),
						EnterpriseNumber:     uint32(29319),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(2),
						FieldLength:          uint16(8),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(1),
						FieldLength:          uint16(8),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(27),
						FieldLength:          uint16(16),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(28),
						FieldLength:          uint16(16),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(10),
						FieldLength:          uint16(4),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(14),
						FieldLength:          uint16(4),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(22),
						FieldLength:          uint16(4),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(21),
						FieldLength:          uint16(4),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(31),
						FieldLength:          uint16(3),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(64),
						FieldLength:          uint16(4),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(7),
						FieldLength:          uint16(2),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(11),
						FieldLength:          uint16(2),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(16),
						FieldLength:          uint16(4),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(17),
						FieldLength:          uint16(4),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(63),
						FieldLength:          uint16(16),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(30),
						FieldLength:          uint16(1),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(29),
						FieldLength:          uint16(1),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(4),
						FieldLength:          uint16(1),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(6),
						FieldLength:          uint16(2),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(5),
						FieldLength:          uint16(1),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(61),
						FieldLength:          uint16(1),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(89),
						FieldLength:          uint16(4),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(302),
						FieldLength:          uint16(4),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(234),
						FieldLength:          uint16(4),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(235),
						FieldLength:          uint16(4),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(52),
						FieldLength:          uint16(1),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(53),
						FieldLength:          uint16(1),
					},
					{
						E:                    bool(false),
						InformationElementID: uint16(198),
						FieldLength:          uint16(8),
					},
				},
			},
		},
	}

	dataSet := ipfix.Set{
		SetID: uint16(256), // Data Template = TemplateID
		Records: []ipfix.Record{
			&ipfix.DataRecord{
				FieldValues: []ipfix.FieldValue{
					{ // 500 srhFlagsIPv6
						Value: []uint8{0xaa},
					},
					{ // 501 srhTagIPv6
						Value: []uint8{0xaa, 0xaa},
					},
					{ // 508 srhActiveSegmentIPv6Type
						Value: []uint8{0x04},
					},
					{ // 255
						Value: []uint8{0xff},
					},
					{ // List Length = 53
						Value: []uint8{0x00, 0x35},
					},
					{ // semantic = ordered
						Value: []uint8{0x04},
					},
					{ // srhSegmentIPv6 = 502
						Value: []uint8{0x01, 0xf6},
					},
					{ // Field Length = 16
						Value: []uint8{0x00, 0x10},
					},
					{ // 502 srhSegmentIPv6
						Value: []uint8{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
					},
					{ // 502 srhSegmentIPv6
						Value: []uint8{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
					},
					{ // 502 srhSegmentIPv6
						Value: []uint8{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
					},
					{ // 521 PathDelayMeanDeltaMicroseconds
						Value: []uint8{0x00, 0x01},
					},
					{ // 522 PathDelayMeanDeltaNanoseconds
						Value: []uint8{0x00, 0x00, 0x00, 0x01},
					},
					{ // 523 PathDelayMinDeltaMicroseconds
						Value: []uint8{0x00, 0x01},
					},
					{ // 524 name=PathDelayMinDeltaNanoseconds
						Value: []uint8{0x00, 0x00, 0x00, 0x01},
					},
					{ // 525 name=PathDelayMaxDeltaMicroseconds
						Value: []uint8{0x00, 0x01},
					},
					{ // 526 name=PathDelayMaxDeltaNanoseconds
						Value: []uint8{0x00, 0x00, 0x00, 0x01},
					},
					{ // 527 name=PathDelaySumDeltaMicroseconds
						Value: []uint8{0x00, 0x00, 0x00, 0x01},
					},
					{ // 528 name=PathDelaySumDeltaNanoseconds
						Value: []uint8{0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff},
					},
					{ // 2
						Value: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a},
					},
					{ // 1
						Value: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8},
					},
					{ // 27
						Value: []uint8{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0xdf, 0x37, 0xff, 0xfe, 0xc1, 0x89, 0x58},
					},
					{ // 28
						Value: []uint8{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5e, 0x5a, 0xc7, 0xff, 0xfe, 0x3f, 0x54, 0x99},
					},
					{ // 10
						Value: []uint8{0x00, 0x00, 0x00, 0x43},
					},
					{ // 14
						Value: []uint8{0x00, 0x00, 0x00, 0x00},
					},
					{ // 22
						Value: []uint8{0xd9, 0x1d, 0x78, 0x65},
					},
					{ // 21
						Value: []uint8{0xd9, 0x1d, 0xcd, 0x2d},
					},
					{ // 31
						Value: []uint8{0x05, 0x29, 0x71},
					},
					{ // 64
						Value: []uint8{0x00, 0x00, 0x00, 0x00},
					},
					{ // 7
						Value: []uint8{0x00, 0x00},
					},
					{ // 11
						Value: []uint8{0x00, 0x81},
					},
					{ // 16
						Value: []uint8{0x00, 0x00, 0x00, 0x00},
					},
					{ // 17
						Value: []uint8{0x00, 0x00, 0x00, 0x00},
					},
					{ // 63
						Value: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
					},
					{ // 30
						Value: []uint8{0x00},
					},
					{ // 29
						Value: []uint8{0x00},
					},
					{ // 4
						Value: []uint8{0x3a},
					},
					{ // 6
						Value: []uint8{0x00, 0x00},
					},
					{ // 5
						Value: []uint8{0x00},
					},
					{ // 61
						Value: []uint8{0x00},
					},
					{ // 89
						Value: []uint8{0x00, 0x00, 0x00, 0xc3},
					},
					{ // 302
						Value: []uint8{0x00, 0x00, 0x00, 0x01},
					},
					{ //234
						Value: []uint8{0x60, 0x00, 0x00, 0x00},
					},
					{ // 235
						Value: []uint8{0x00, 0x00, 0x00, 0x00},
					},
					{ // 52
						Value: []uint8{0x40},
					},
					{ // 53
						Value: []uint8{0x40},
					},
					{ // 198
						Value: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xa0},
					},
				},
			},
		},
	}

	templateTicker := time.NewTicker(time.Duration(10) * time.Second)
	defer templateTicker.Stop()
	dataTicker := time.NewTicker(time.Duration(1) * time.Second)
	defer dataTicker.Stop()
	setChan <- templateSet
	for {
		select {
		case <-templateTicker.C:
			setChan <- templateSet
		case <-dataTicker.C:
			setChan <- dataSet
		}
	}
}
