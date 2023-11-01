// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package ipfix

import (
	"encoding/binary"
	"net/netip"
)

type FieldValue interface {
	Serialize() []uint8
	Len() uint16 // binary length of field value
	ElementID() uint16
	FieldSpecifier() *FieldSpecifier
}

type PacketDeltaCount struct {
	Val uint64
}

func (fv *PacketDeltaCount) ElementID() uint16 {
	return IEID_PACKET_DELTA_COUNT
}

func (fv *PacketDeltaCount) Serialize() []uint8 {
	ret := make([]uint8, 8)
	binary.BigEndian.PutUint64(ret, fv.Val)
	return ret
}

func (fv *PacketDeltaCount) Len() uint16 {
	return 8
}

func (fv *PacketDeltaCount) FieldSpecifier() *FieldSpecifier {
	templateLen := fv.Len()
	fs := NewFieldSpecifier(false, fv.ElementID(), templateLen, ENTERPRISE_NUMBER_NTTCOM)
	return fs
}

type SRHFlagsIPv6 struct {
	Val uint8
}

func (fv *SRHFlagsIPv6) ElementID() uint16 {
	return IEID_SRH_FLAGS_IPV6
}

func (fv *SRHFlagsIPv6) Serialize() []uint8 {
	return []uint8{fv.Val}
}

func (fv *SRHFlagsIPv6) Len() uint16 {
	return 1
}

func (fv *SRHFlagsIPv6) FieldSpecifier() *FieldSpecifier {
	templateLen := fv.Len()
	fs := NewFieldSpecifier(false, fv.ElementID(), templateLen, ENTERPRISE_NUMBER_NTTCOM)
	return fs
}

type SRHTagIPv6 struct {
	Val uint16
}

func (fv *SRHTagIPv6) ElementID() uint16 {
	return IEID_SRH_TAG_IPV6
}

func (fv *SRHTagIPv6) Serialize() []uint8 {
	ret := make([]uint8, 2)
	binary.BigEndian.PutUint16(ret, fv.Val)
	return ret
}

func (fv *SRHTagIPv6) Len() uint16 {
	return 2
}

func (fv *SRHTagIPv6) FieldSpecifier() *FieldSpecifier {
	templateLen := fv.Len()
	fs := NewFieldSpecifier(false, fv.ElementID(), templateLen, ENTERPRISE_NUMBER_NTTCOM)
	return fs
}

type SRHSegmentIPv6 struct {
	Val netip.Addr
}

func (fv *SRHSegmentIPv6) ElementID() uint16 {
	return IEID_SRH_ACTIVE_SEGMENT_IPV6
}

func (fv *SRHSegmentIPv6) Serialize() []uint8 {
	return fv.Val.AsSlice()
}

func (fv *SRHSegmentIPv6) Len() uint16 {
	return 16
}

func (fv *SRHSegmentIPv6) FieldSpecifier() *FieldSpecifier {
	templateLen := fv.Len()
	fs := NewFieldSpecifier(false, fv.ElementID(), templateLen, ENTERPRISE_NUMBER_NTTCOM)
	return fs
}

type SRHActiveSegmentIPv6 struct {
	Val netip.Addr
}

func (fv *SRHActiveSegmentIPv6) ElementID() uint16 {
	return IEID_SRH_ACTIVE_SEGMENT_IPV6
}

func (fv *SRHActiveSegmentIPv6) Serialize() []uint8 {
	return fv.Val.AsSlice()
}

func (fv *SRHActiveSegmentIPv6) Len() uint16 {
	return 16
}

func (fv *SRHActiveSegmentIPv6) FieldSpecifier() *FieldSpecifier {
	templateLen := fv.Len()
	fs := NewFieldSpecifier(false, fv.ElementID(), templateLen, ENTERPRISE_NUMBER_NTTCOM)
	return fs
}

type SRHSegmentIPv6BasicList struct {
	SegmentList []SRHSegmentIPv6
}

func (fv *SRHSegmentIPv6BasicList) ElementID() uint16 {
	return IEID_SRH_SEGMENT_IPV6_BASIC_LIST
}

func (fv *SRHSegmentIPv6BasicList) Serialize() []uint8 {
	ret := []uint8{}

	ret = append(ret, 255)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, uint16(len(fv.SegmentList)*16+5))
	ret = append(ret, length...)

	ret = append(ret, 4) // ordered

	subElemID := make([]uint8, 2)
	binary.BigEndian.PutUint16(subElemID, IEID_SRH_SEGMENT_IPV6)
	ret = append(ret, subElemID...)

	subElemLength := make([]uint8, 2)
	binary.BigEndian.PutUint16(subElemLength, 16) // SRv6 SID Length
	ret = append(ret, subElemLength...)

	for _, sl := range fv.SegmentList {
		ret = append(ret, sl.Serialize()...)
	}
	return ret
}

func (fv *SRHSegmentIPv6BasicList) Len() uint16 {
	return uint16(16*len(fv.SegmentList) + 6)
}

func (fv *SRHSegmentIPv6BasicList) FieldSpecifier() *FieldSpecifier {
	templateLen := uint16(0xffff) // valiable
	fs := NewFieldSpecifier(false, fv.ElementID(), templateLen, ENTERPRISE_NUMBER_NTTCOM)
	return fs
}

type SRHSegmentIPv6ListSection struct {
	SegmentList []netip.Addr
}

func (fv *SRHSegmentIPv6ListSection) ElementID() uint16 {
	return IEID_SRH_SEGMENT_IPV6_LIST_SECTION
}

func (fv *SRHSegmentIPv6ListSection) Serialize() []uint8 {
	ret := []uint8{}

	length := uint8(len(fv.SegmentList) * 16)
	ret = append(ret, length)

	for _, sl := range fv.SegmentList {
		ret = append(ret, sl.AsSlice()...)
	}
	return ret
}

func (fv *SRHSegmentIPv6ListSection) Len() uint16 {
	return uint16(16*len(fv.SegmentList) + 1)
}

func (fv *SRHSegmentIPv6ListSection) FieldSpecifier() *FieldSpecifier {
	templateLen := uint16(0xffff) // valiable
	fs := NewFieldSpecifier(false, fv.ElementID(), templateLen, ENTERPRISE_NUMBER_NTTCOM)
	return fs
}

type SRHSegmentsIPv6Left struct {
	Val uint8
}

func (fv *SRHSegmentsIPv6Left) ElementID() uint16 {
	return IEID_SRH_SEGMENT_IPV6_LEFT
}

func (fv *SRHSegmentsIPv6Left) Serialize() []uint8 {
	return []uint8{fv.Val}
}

func (fv *SRHSegmentsIPv6Left) Len() uint16 {
	return 1
}

func (fv *SRHSegmentsIPv6Left) FieldSpecifier() *FieldSpecifier {
	templateLen := fv.Len()
	fs := NewFieldSpecifier(false, fv.ElementID(), templateLen, ENTERPRISE_NUMBER_NTTCOM)
	return fs
}

type SRHIPv6ActiveSegmentType struct {
	Val uint8
}

func (fv *SRHIPv6ActiveSegmentType) ElementID() uint16 {
	return IEID_SRH_IPV6_ACTIVE_SEGMENT_TYPE
}

func (fv *SRHIPv6ActiveSegmentType) Serialize() []uint8 {
	return []uint8{fv.Val}
}

func (fv *SRHIPv6ActiveSegmentType) Len() uint16 {
	return 1
}

func (fv *SRHIPv6ActiveSegmentType) FieldSpecifier() *FieldSpecifier {
	templateLen := fv.Len()
	fs := NewFieldSpecifier(false, fv.ElementID(), templateLen, ENTERPRISE_NUMBER_NTTCOM)
	return fs
}

type SRHSegmentIPv6LocatorLength struct {
	Val uint8
}

func (fv *SRHSegmentIPv6LocatorLength) ElementID() uint16 {
	return IEID_SRH_SEGMENT_IPV6_LOCATOR_LENGTH
}

func (fv *SRHSegmentIPv6LocatorLength) Serialize() []uint8 {
	return []uint8{fv.Val}
}

func (fv *SRHSegmentIPv6LocatorLength) Len() uint16 {
	return 1
}

func (fv *SRHSegmentIPv6LocatorLength) FieldSpecifier() *FieldSpecifier {
	templateLen := fv.Len()
	fs := NewFieldSpecifier(false, fv.ElementID(), templateLen, ENTERPRISE_NUMBER_NTTCOM)
	return fs
}

type SRHSegmentIPv6EndpointBehavior struct {
	Val uint16
}

func (fv *SRHSegmentIPv6EndpointBehavior) ElementID() uint16 {
	return IEID_SRH_SEGMENT_IPV6_ENDPOINT_BEHAVIOR
}

func (fv *SRHSegmentIPv6EndpointBehavior) Serialize() []uint8 {
	ret := make([]uint8, 2)
	binary.BigEndian.PutUint16(ret, fv.Val)
	return ret
}

func (fv *SRHSegmentIPv6EndpointBehavior) Len() uint16 {
	return 2
}

func (fv *SRHSegmentIPv6EndpointBehavior) FieldSpecifier() *FieldSpecifier {
	templateLen := fv.Len()
	fs := NewFieldSpecifier(false, fv.ElementID(), templateLen, ENTERPRISE_NUMBER_NTTCOM)
	return fs
}

type UndefinedFieldValue struct {
	ElemID           uint16
	Value            []uint8
	TemplateLen      uint16
	EnterpriseNumber uint32
}

func (fv *UndefinedFieldValue) ElementID() uint16 {
	return fv.ElemID
}

func (fv *UndefinedFieldValue) Serialize() []uint8 {
	return fv.Value
}

func (fv *UndefinedFieldValue) Len() uint16 {
	return uint16(len(fv.Value))
}

func (fv *UndefinedFieldValue) FieldSpecifier() *FieldSpecifier {
	var fs *FieldSpecifier
	if fv.EnterpriseNumber != 0 {
		fs = NewFieldSpecifier(true, fv.ElementID(), fv.TemplateLen, fv.EnterpriseNumber)
	} else {
		fs = NewFieldSpecifier(false, fv.ElementID(), fv.TemplateLen, fv.EnterpriseNumber)
	}
	return fs
}

const ENTERPRISE_NUMBER_NTTCOM uint32 = 29319 // NTT Communications

const (
	IEID_OCTET_DELTA_COUNT                uint16 = 1  // RFC5102
	IEID_PACKET_DELTA_COUNT               uint16 = 2  // RFC5102
	IEID_DELTA_FLOW_COUNT                 uint16 = 3  // RFC7015
	IEID_PROTOCOL_IDENTIFIER              uint16 = 4  // RFC5102
	IEID_IP_CLASS_OF_SERVICE              uint16 = 5  // RFC5102
	IEID_TCP_CONTROL_BITS                 uint16 = 6  // RFC5102
	IEID_SOURCE_TRANSPORT_PORT            uint16 = 7  // RFC5102
	IEID_SOURCE_IPV4_ADDRESS              uint16 = 8  // RFC5102
	IEID_SOURCE_IPV4_PREFIX_LENGTH        uint16 = 9  // RFC5102
	IEID_INGRESS_INTERFACE                uint16 = 10 // RFC5102
	IEID_DESTINATION_TRANSPORT_PORT       uint16 = 11 // RFC5102
	IEID_DESTINATION_IPV4_ADDRESS         uint16 = 12 // RFC5102
	IEID_DEATINATION_IPV4_PREFIX_LENGTH   uint16 = 13 // RFC5102
	IEID_EGRESS_INTERFACE                 uint16 = 14 // RFC5102
	IEID_IP_NEXT_HOP_IPV4_ADDRESS         uint16 = 15 // RFC5102
	IEID_BGP_SOURCE_AS_NUMBER             uint16 = 16 // RFC5102
	IEID_BGP_DESTINATION_AS_NUMBER        uint16 = 17 // RFC5102
	IEID_BGP_NEXT_HOP_IPV4_ADDRESS        uint16 = 18 // RFC5102
	IEID_POST_MCAST_PACKET_DELTA_COUNT    uint16 = 19 // RFC5102
	IEID_POST_MCAST_OCTET_DELTA_COUNT     uint16 = 20 // RFC5102
	IEID_FLOW_END_SYS_UP_TIME             uint16 = 21 // RFC5102
	IEID_FLOW_START_SYS_UP_TIME           uint16 = 22 // RFC5102
	IEID_POST_OCTET_DELTA_COUNT           uint16 = 23 // RFC5102
	IEID_POST_PACKET_DELTA_COUNT          uint16 = 24 // RFC5102
	IEID_MINIMUM_IP_TOTAL_LENGTH          uint16 = 25 // RFC5102
	IEID_MAXIMUM_IP_TOTAL_LENGTH          uint16 = 26 // RFC5102
	IEID_SOURCE_IPV6_ADDRESS              uint16 = 27 // RFC5102
	IEID_DESTINATION_IPV6_ADDRESS         uint16 = 28 // RFC5102
	IEID_SOURCE_IPV6_PREFIX_LENGTH        uint16 = 29 // RFC5102
	IEID_DESTINATION_IPV6_PREFIX_LENGTH   uint16 = 30 // RFC5102
	IEID_FLOW_LABEL_IPV6                  uint16 = 31 // RFC5102
	IEID_ICMP_TYPE_CODE_IPV4              uint16 = 32 // RFC5102
	IEID_IGMP_TYPE                        uint16 = 33 // RFC5102
	IEID_SAMPLING_INTERVAL                uint16 = 34 // RFC7270
	IEID_SAMPLING_ALGORITHM               uint16 = 35 // RFC7270
	IEID_FLOW_ACTIVE_TIMEOUT              uint16 = 36 // RFC5102
	IEID_FLOW_INACTIVE_TIMEOUT            uint16 = 37 // RFC5102
	IEID_ENGINE_TYPE                      uint16 = 38 // RFC7270
	IEID_ENGINE_ID                        uint16 = 39 // RFC7270
	IEID_EXPORTED_OCTET_TOTAL_COUNT       uint16 = 40 // RFC5102
	IEID_EXPORTED_MESSAGE_TOTAL_COUNT     uint16 = 41 // RFC5102
	IEID_EXPORTED_FLOW_RECORD_TOTAL_COUNT uint16 = 42 // RFC5102
	IEID_IPV4_ROUTER_SC                   uint16 = 43 // RFC7270
	IEID_SOURCE_IPV4_PREFIX               uint16 = 44 // RFC5102
	IEID_DESTINATION_IPV4_PREFIX          uint16 = 45 // RFC5102
	IEID_MPLS_TOP_LABEL_TYPE              uint16 = 46 // RFC5102
	IEID_MPLS_TOP_LABEL_IPV4_ADDRESS      uint16 = 47 // RFC5102
	IEID_SAMPLER_ID                       uint16 = 48 // RFC7270
	IEID_SAMPLER_MODE                     uint16 = 49 // RFC7270
	IEID_SAMPLER_RANDOM_INTERVAL          uint16 = 50 // RFC7270
	IEID_CLASS_ID                         uint16 = 51 // RFC7270
	IEID_MINIMUM_TTL                      uint16 = 52 // RFC5102
	IEID_MAXIMUM_TTL                      uint16 = 53 // RFC5102
	IEID_FRAGMENT_IDENTIFICATION          uint16 = 54 // RFC5102
	IEID_POST_IP_CLASS_OF_SERVICE         uint16 = 55 // RFC5102
	IEID_SOURCE_MAC_ADDRESS               uint16 = 56 // RFC5102
	IEID_POST_DESTINATION_MAC_ADDRESS     uint16 = 57 // RFC5102
	IEID_VLAN_ID                          uint16 = 58 // RFC5102
	IEID_POST_VLAN_ID                     uint16 = 59 // RFC5102
	IEID_IP_VERSION                       uint16 = 60 // RFC5102
	IEID_FLOW_DIRECTION                   uint16 = 61 // RFC5102
	IEID_IP_NEXT_HOP_IPV6_ADDRESS         uint16 = 62 // RFC5102
	IEID_BGP_NEXT_HOP_IPV6_ADDRESS        uint16 = 63 // RFC5102
	IEID_IPV6_EXTENSION_HEADERS           uint16 = 64 // RFC5102
	IEID_MPLS_TOP_LABEL_STACK_SECTION     uint16 = 70 // RFC5102
	IEID_MPLS_LABEL_STACK_SECTION2        uint16 = 71 // RFC5102
	IEID_MPLS_LABEL_STACK_SECTION3        uint16 = 72 // RFC5102
	IEID_MPLS_LABEL_STACK_SECTION4        uint16 = 73 // RFC5102
	IEID_MPLS_LABEL_STACK_SECTION5        uint16 = 74 // RFC5102
	IEID_MPLS_LABEL_STACK_SECTION6        uint16 = 75 // RFC5102
	IEID_MPLS_LABEL_STACK_SECTION7        uint16 = 76 // RFC5102
	IEID_MPLS_LABEL_STACK_SECTION8        uint16 = 77 // RFC5102
	IEID_MPLS_LABEL_STACK_SECTION9        uint16 = 78 // RFC5102
	IEID_MPLS_LABEL_STACK_SECTION10       uint16 = 79 // RFC5102
	IEID_DESTINATION_MAC_ADDRESS          uint16 = 80 // RFC5102
	IEID_POST_SOURCE_MAC_ADDRESS          uint16 = 81 // RFC5102
	IEID_INTERFACE_NAME                   uint16 = 82 // ipfix-iana_at_cisco.com
	IEID_INTERFACE_DESCRIPTION            uint16 = 83 // ipfix-iana_at_cisco.com
	IEID_SAMPLER_NAME                     uint16 = 84 // RFC7270
	IEID_OCTET_TOTAL_COUNT                uint16 = 85 // RFC5102
	IEID_PACKET_TOTAL_COUNT               uint16 = 86 // RFC5102
	IEID_FLAGS_AND_SAMPLING_ID            uint16 = 87 // RFC7270
	IEID_FRAGMENT_OFFSET                  uint16 = 88 // RFC5102
	IEID_FOREARDING_STATUS                uint16 = 89 // RFC7270, RFC Errata 5262
	IEID_MPLS_VPN_ROUTE_DISTINGUISHER     uint16 = 90 // RFC5102
	IEID_MPLS_TOP_LABEL_PREFIX_LENGTH     uint16 = 91 // ipfix-iana_at_cisco.com
	IEID_SRC_TRAFFIC_INDEX                uint16 = 92 // RFC7270
	IEID_DST_TRAFFIC_INDEX                uint16 = 93 // RFC7270
	IEID_APPLICATION_DESCRIPTION          uint16 = 94 // RFC6759
	IEID_APPLICATION_ID                   uint16 = 95 // RFC6759
	IEID_APPLICATION_NAME                 uint16 = 96 // RFC6759
	// 97: Assigned for NetFlow v9 compatibility (RFC5102)
	IEID_POST_IP_DIFF_SERV_CODE_POINT uint16 = 98  // ipfix-iana_at_cisco.com
	IEID_MULTICAST_REPLICATION_FACTOR uint16 = 99  // ipfix-iana_at_cisco.com
	IEID_CLASS_NAME                   uint16 = 100 // RFC7270
	IEID_CLASSIFICATION_ENGINE_ID     uint16 = 101 // RFC6759
	IEID_LAYER2_PACKET_SECTION_OFFSET uint16 = 102 // RFC7270
	IEID_LAYER2_PACKET_SECTION_SIZE   uint16 = 103 // RFC7270
	IEID_LAYER2_PACKET_SECTION_DATA   uint16 = 104 // RFC7270
	// 105-127: Assigned for NetFlow v9 compatibility (RFC5102)
	IEID_BGP_NEXT_ADJACENT_AS_NUMBER                uint16 = 128 // RFC5102
	IEID_BGP_PREV_ADJACENT_AS_NUMBER                uint16 = 129 // RFC5102
	IEID_EXPORTER_IPV4_ADDRESS                      uint16 = 130 // RFC5102
	IEID_EXPORTER_IPV6_ADDRESS                      uint16 = 131 // RFC5102
	IEID_DROPPED_OCTET_DELTA_COUNT                  uint16 = 132 // RFC5102
	IEID_DROPPED_PACKET_DELTA_COUNT                 uint16 = 133 // RFC5102
	IEID_DROPPED_OCTET_TOTAL_COUNT                  uint16 = 134 // RFC5102
	IEID_DROPPED_PACKET_TOTAL_COUNT                 uint16 = 135 // RFC5102
	IEID_FLOW_END_REASON                            uint16 = 136 // RFC5102
	IEID_COMMON_PROPERTIES_ID                       uint16 = 137 // RFC5102
	IEID_OBSERVATION_POINT_ID                       uint16 = 138 // RFC5102, ipfix-iana_at_cisco.com
	IEID_ICMP_TYPE_CODE_IPV6                        uint16 = 139 // RFC5102
	IEID_MPLS_TOP_LABEL_IPV6_ADDRESS                uint16 = 140 // RFC5102
	IEID_LINE_CARD_ID                               uint16 = 141 // RFC5102
	IEID_PORT_ID                                    uint16 = 142 // RFC5102
	IEID_METERING_PROCESS_ID                        uint16 = 143 // RFC5102
	IEID_EXPORTING_PROCESS_ID                       uint16 = 144 // RFC5102
	IEID_TEMPLATE_ID                                uint16 = 145 // RFC5102
	IEID_WLAN_CHANNEL_ID                            uint16 = 146 // RFC5102
	IEID_WLAN_SSID                                  uint16 = 147 // RFC5102
	IEID_FLOW_ID                                    uint16 = 148 // RFC5102
	IEID_OBSERVATION_DOMAIN_ID                      uint16 = 149 // RFC5102
	IEID_FLOW_START_SECONDS                         uint16 = 150 // RFC5102
	IEID_FLOW_END_SECONDS                           uint16 = 151 // RFC5102
	IEID_FLOW_START_MILLISECONDS                    uint16 = 152 // RFC5102
	IEID_FLOW_END_MILLISECONDS                      uint16 = 153 // RFC5102
	IEID_FLOW_START_MICROSECONDS                    uint16 = 154 // RFC5102
	IEID_FLOW_END_MICROSECONDS                      uint16 = 155 // RFC5102
	IEID_FLOW_START_NANOSECONDS                     uint16 = 156 // RFC5102
	IEID_FLOW_END_NANOSECONDS                       uint16 = 157 // RFC5102
	IEID_FLOW_START_DELTA_MICROSECONDS              uint16 = 158 // RFC5102
	IEID_FLOW_END_DELTA_MICROSECONDS                uint16 = 159 // RFC5102
	IEID_SYSTEM_INIT_TIME_MILLISECONDS              uint16 = 160 // RFC5102
	IEID_FLOW_DURATION_MILLISECONDS                 uint16 = 161 // RFC5102
	IEID_FLOW_DURATION_MICROSECONDS                 uint16 = 162 // RFC5102
	IEID_OBSERVED_FLOW_TOTAL_COUNT                  uint16 = 163 // RFC5102
	IEID_IGNORED_PACKET_TOTAL_COUNT                 uint16 = 164 // RFC5102
	IEID_IGNORED_OCTET_TOTAL_COUNT                  uint16 = 165 // RFC5102
	IEID_NOT_SENT_FLOW_TOTAL_COUNT                  uint16 = 166 // RFC5102
	IEID_NOT_SENT_PACKET_TOTAL_COUNT                uint16 = 167 // RFC5102
	IEID_NOT_SENT_OCTET_TOTAL_COUNT                 uint16 = 168 // RFC5102
	IEID_DESTINATION_IPV6_PREFIX                    uint16 = 169 // RFC5102
	IEID_SOURCE_IPV6_PREFIX                         uint16 = 170 // RFC5102
	IEID_POST_OCTET_TOTAL_COUNT                     uint16 = 171 // RFC5102
	IEID_POST_PACKET_TOTAL_COUNT                    uint16 = 172 // RFC5102
	IEID_FLOW_KEY_INDICATOR                         uint16 = 173 // RFC5102, RFC Errata 4984
	IEID_POST_MCAST_PACKET_TOTAL_COUNT              uint16 = 174 // RFC5102
	IEID_POST_MCAST_OCTET_TOTAL_COUNT               uint16 = 175 // RFC5102
	IEID_ICMP_TYPE_IPV4                             uint16 = 176 // RFC5102
	IEID_ICMP_CODE_IPV4                             uint16 = 177 // RFC5102
	IEID_ICMP_TYPE_IPV6                             uint16 = 178 // RFC5102
	IEID_ICMP_CODE_IPV6                             uint16 = 179 // RFC5102
	IEID_UDP_SOURCE_PORT                            uint16 = 180 // RFC5102
	IEID_UDP_DESTINATION_PORT                       uint16 = 181 // RFC5102
	IEID_TCP_SOURCE_PORT                            uint16 = 182 // RFC5102
	IEID_TCP_DESTINATION_PORT                       uint16 = 183 // RFC5102
	IEID_TCP_SEQUENCE_NUMBER                        uint16 = 184 // RFC5102
	IEID_TCP_ACKNOWLEDGEMENT_NUMBER                 uint16 = 185 // RFC5102
	IEID_TCP_WINDOW_SIZE                            uint16 = 186 // RFC5102
	IEID_TCP_URGENT_POINTER                         uint16 = 187 // RFC5102
	IEID_TCP_HEADER_LENGTH                          uint16 = 188 // RFC5102
	IEID_IP_HEADER_LENGTH                           uint16 = 189 // RFC5102
	IEID_TOTAL_LENGTH_IPV4                          uint16 = 190 // RFC5102
	IEID_PAYLOAD_LENGTH_IPV6                        uint16 = 191 // RFC5102
	IEID_IP_TTL                                     uint16 = 192 // RFC5102
	IEID_NEXT_HEADER_IPV6                           uint16 = 193 // RFC5102
	IEID_MPLS_PAYLOAD_LENGTH                        uint16 = 194 // RFC5102
	IEID_IP_DIFF_SERV_CODE_POINT                    uint16 = 195 // RFC5102
	IEID_IP_PRECEDENCE                              uint16 = 196 // RFC5102
	IEID_FRAGMENT_FLAGS                             uint16 = 197 // RFC5102
	IEID_OCTET_DELTA_SUM_OF_SQUARES                 uint16 = 198 // RFC5102
	IEID_OCTET_TOTAL_SUM_OF_SQUARES                 uint16 = 199 // RFC5102
	IEID_MPLS_TOP_LABEL_TTL                         uint16 = 200 // RFC5102
	IEID_MPLS_LABEL_STACK_LENGTH                    uint16 = 201 // RFC5102
	IEID_MPLS_LABEL_STACK_DEPTH                     uint16 = 202 // RFC5102
	IEID_MPLS_TOP_LABEL_EXP                         uint16 = 203 // RFC5102
	IEID_IP_PAYLOAD_LENGTH                          uint16 = 204 // RFC5102
	IEID_UDP_MESSAGE_LENGTH                         uint16 = 205 // RFC5102
	IEID_IS_MULTICAST                               uint16 = 206 // RFC5102
	IEID_IPV4_IHL                                   uint16 = 207 // RFC5102
	IEID_IPV4_OPTIONS                               uint16 = 208 // RFC5102
	IEID_TCP_OPTIONS                                uint16 = 209 // RFC5102
	IEID_PADDING_OCTETS                             uint16 = 210 // RFC5102
	IEID_COLLECTOR_IPV4_ADDRESS                     uint16 = 211 // RFC5102
	IEID_COLLECTOR_IPV6_ADDRESS                     uint16 = 212 // RFC5102
	IEID_EXPORT_INTERFACE                           uint16 = 213 // RFC5102
	IEID_EXPORT_PROTOCOL_VERSION                    uint16 = 214 // RFC5102
	IEID_EXPORT_TRANSPORT_PROTOCOL                  uint16 = 215 // RFC5102
	IEID_COLLECTOR_TRANSPORT_PORT                   uint16 = 216 // RFC5102
	IEID_EXPORTER_TRANSPORT_PORT                    uint16 = 217 // RFC5102
	IEID_TCP_SYN_TOTAL_COUNT                        uint16 = 218 // RFC5102
	IEID_TCP_FIN_TOTAL_COUNT                        uint16 = 219 // RFC5102
	IEID_TCP_RST_TOTAL_COUNT                        uint16 = 220 // RFC5102
	IEID_TCP_PSH_TOTAL_COUNT                        uint16 = 221 // RFC5102
	IEID_TCP_ACK_TOTAL_COUNT                        uint16 = 222 // RFC5102
	IEID_TCP_URG_TOTAL_COUNT                        uint16 = 223 // RFC5102
	IEID_IP_TOTAL_LENGTH                            uint16 = 224 // RFC5102
	IEID_POST_NAT_SOURCE_IPV4_ADDRESS               uint16 = 225 // ipfix-iana_at_cisco.com
	IEID_POST_NAT_DESTINATION_IPV4_ADDRESS          uint16 = 226 // ipfix-iana_at_cisco.com
	IEID_POST_NAPT_SOURCE_TRANSPORT_PORT            uint16 = 227 // ipfix-iana_at_cisco.com
	IEID_POST_NAPT_DESTINATION_TRANSPORT_PORT       uint16 = 228 // ipfix-iana_at_cisco.com
	IEID_NAT_ORIGINATING_ADDRESS_REALM              uint16 = 229 // ipfix-iana_at_cisco.com
	IEID_NAT_EVENT                                  uint16 = 230 // RFC8158
	IEID_INITIATOR_OCTETS                           uint16 = 231 // ipfix-iana_at_cisco.com
	IEID_RESPONDER_OCTETS                           uint16 = 232 // ipfix-iana_at_cisco.com
	IEID_FIREWALL_EVENT                             uint16 = 233 // ipfix-iana_at_cisco.com
	IEID_INGRESS_VRFID                              uint16 = 234 // ipfix-iana_at_cisco.com
	IEID_EGRESS_VRFID                               uint16 = 235 // ipfix-iana_at_cisco.com
	IEID_VRF_NAME                                   uint16 = 236 // ipfix-iana_at_cisco.com
	IEID_POST_MPLS_TOP_LABEL_EXP                    uint16 = 237 // RFC5102
	IEID_TCP_WINDOW_SCALE                           uint16 = 238 // RFC5102
	IEID_BIFLOW_DIRECTION                           uint16 = 239 // RFC5103
	IEID_ETHERNET_HEADER_LENGTH                     uint16 = 240 // ipfix-iana_at_cisco.com
	IEID_ETHERNET_PAYLOAD_LENGTH                    uint16 = 241 // ipfix-iana_at_cisco.com
	IEID_ETHERNET_TOTAL_LENGTH                      uint16 = 242 // ipfix-iana_at_cisco.com
	IEID_DOT1Q_VLAN_ID                              uint16 = 243 // ipfix-iana_at_cisco.com, RFC7133
	IEID_DOT1Q_PRIORITY                             uint16 = 244 // ipfix-iana_at_cisco.com, RFC7133
	IEID_DOT1Q_CUSTOMER_VLAN_ID                     uint16 = 245 // ipfix-iana_at_cisco.com, RFC7133
	IEID_DOT1Q_CUSTOMER_PRIORITY                    uint16 = 246 // ipfix-iana_at_cisco.com, RFC7133
	IEID_METRO_EVC_ID                               uint16 = 247 // ipfix-iana_at_cisco.com
	IEID_METRO_EVC_TYPE                             uint16 = 248 // ipfix-iana_at_cisco.com
	IEID_PSEUDO_WIRE_ID                             uint16 = 249 // ipfix-iana_at_cisco.com
	IEID_PSEUDO_WIRE_TYPE                           uint16 = 250 // ipfix-iana_at_cisco.com
	IEID_PSEUDO_WIRE_CONTROL_WORD                   uint16 = 251 // ipfix-iana_at_cisco.com
	IEID_INGRESS_PHYSICAL_INTERFACE                 uint16 = 252 // ipfix-iana_at_cisco.com
	IEID_EGRESS_PHYSICAL_INTERFACE                  uint16 = 253 // ipfix-iana_at_cisco.com
	IEID_POST_DOT1Q_VLAN_ID                         uint16 = 254 // ipfix-iana_at_cisco.com
	IEID_POST_DOT1Q_CUSTOMER_VLAN_ID                uint16 = 255 // ipfix-iana_at_cisco.com
	IEID_ETHERNET_TYPE                              uint16 = 256 // ipfix-iana_at_cisco.com
	IEID_POST_IP_PRECEDENCE                         uint16 = 257 // ipfix-iana_at_cisco.com
	IEID_COLLECTION_TIME_MILLISECONDS               uint16 = 258 // RFC5655, RFC Errata 3559
	IEID_EXPORT_SCTP_STREAM_ID                      uint16 = 259 // RFC5655
	IEID_MAX_EXPORT_SECONDS                         uint16 = 260 // RFC5655
	IEID_MAX_FLOW_END_SECONDS                       uint16 = 261 // RFC5655
	IEID_MESSAGE_MD5_CHECKSUM                       uint16 = 262 // RFC5655, RFC1321
	IEID_MESSAGE_SCOPE                              uint16 = 263 // RFC5655
	IEID_MIN_EXPORT_SECONDS                         uint16 = 264 // RFC5655
	IEID_MIN_FLOW_START_SECONDS                     uint16 = 265 // RFC5655
	IEID_OPAQUE_OCTETS                              uint16 = 266 // RFC5655
	IEID_SESSION_SCOPE                              uint16 = 267 // RFC5655
	IEID_MAX_FLOW_END_MICROSECONDS                  uint16 = 268 // RFC5655
	IEID_MAX_FLOW_END_MILLISECONDS                  uint16 = 269 // RFC5655
	IEID_MAX_FLOW_END_NANOSECONDS                   uint16 = 270 // RFC5655
	IEID_MIN_FLOW_START_MICROSECONDS                uint16 = 271 // RFC5655
	IEID_MIN_FLOW_START_MILLISECONDS                uint16 = 272 // RFC5655
	IEID_MIN_FLOW_START_NANOSECONDS                 uint16 = 273 // RFC5655
	IEID_COLLECTOR_CERTIFICATE                      uint16 = 274 // RFC5655
	IEID_EXPORTER_CERTIFICATE                       uint16 = 275 // RFC5655
	IEID_DATA_RECORDS_RELIABILITY                   uint16 = 276 // RFC6526
	IEID_OBSERVATION_POINT_TYPE                     uint16 = 277 // ipfix-iana_at_cisco.com
	IEID_NEW_CONNECTION_DELTA_COUNT                 uint16 = 278 // ipfix-iana_at_cisco.com
	IEID_CONNECTION_SUM_DURATION_SECONDS            uint16 = 279 // ipfix-iana_at_cisco.com
	IEID_CONNECTION_TRANSACTION_ID                  uint16 = 280 // ipfix-iana_at_cisco.com
	IEID_POST_NAT_SOURCE_IPV6_ADDRESS               uint16 = 281 // ipfix-iana_at_cisco.com
	IEID_POST_NAT_DESTINATION_IPV6_ADDRESS          uint16 = 282 // ipfix-iana_at_cisco.com
	IEID_NAT_POOL_ID                                uint16 = 283 // ipfix-iana_at_cisco.com
	IEID_NAT_POOL_NAME                              uint16 = 284 // ipfix-iana_at_cisco.com
	IEID_ANONYMIZATION_FLAGS                        uint16 = 285 // RFC6235
	IEID_ANONYMIZATION_TECHNIQUE                    uint16 = 286 // RFC6235
	IEID_INFORMATION_ELEMENT_INDEX                  uint16 = 287 // RFC6235
	IEID_P2P_TECHNOLOGY                             uint16 = 288 // RFC6759
	IEID_TUNNEL_TECHNOLOGY                          uint16 = 289 // RFC6759
	IEID_ENCRYPTED_TECHNOLOGY                       uint16 = 290 // RFC6759
	IEID_BASIC_LIST                                 uint16 = 291 // RFC6313
	IEID_SUB_TEMPLATE_LIST                          uint16 = 292 // RFC6313
	IEID_SUB_TEMPLATE_MULTI_LIST                    uint16 = 293 // RFC6313
	IEID_BGP_VALIDITY_STATE                         uint16 = 294 // ipfix-iana_at_cisco.com
	IEID_IPSEC_SPI                                  uint16 = 295 // ipfix-iana_at_cisco.com
	IEID_GRE_KEY                                    uint16 = 296 // ipfix-iana_at_cisco.com
	IEID_NAT_TYPE                                   uint16 = 297 // ipfix-iana_at_cisco.com
	IEID_INITIATOR_PACKETS                          uint16 = 298 // ipfix-iana_at_cisco.com
	IEID_RESPONDER_PACKETS                          uint16 = 299 // ipfix-iana_at_cisco.com
	IEID_OBSERVATION_DOMAIN_NAME                    uint16 = 300 // ipfix-iana_at_cisco.com
	IEID_SELECTION_SEQUENCE_ID                      uint16 = 301 // RFC5477
	IEID_SELECTOR_ID                                uint16 = 302 // RFC5477, RFC Errata 2052
	IEID_INFORMATION_ELEMENT_ID                     uint16 = 303 // RFC5477
	IEID_SELECTOR_ALGORITHM                         uint16 = 304 // RFC5477
	IEID_SAMPLING_PACKET_INTERVAL                   uint16 = 305 // RFC5477
	IEID_SAMPLING_PACKET_SPACE                      uint16 = 306 // RFC5477
	IEID_SAMPLING_TIME_INTERVAL                     uint16 = 307 // RFC5477
	IEID_SAMPLING_TIME_SPACE                        uint16 = 308 // RFC5477
	IEID_SAMPLING_SIZE                              uint16 = 309 // RFC5477
	IEID_SAMPLING_POPULATION                        uint16 = 310 // RFC5477
	IEID_SAMPLING_PROBABILITY                       uint16 = 311 // RFC5477
	IEID_DATA_LINK_FRAME_SIZE                       uint16 = 312 // RFC7133
	IEID_IP_HEADER_PACKET_SECTION                   uint16 = 313 // RFC5477, RFC7133
	IEID_IP_PAYLOAD_PACKET_SECTION                  uint16 = 314 // RFC5477, RFC7133
	IEID_DATA_LINK_FRAME_SECTION                    uint16 = 315 // RFC7133
	IEID_MPLS_LABEL_STACK_SECTION                   uint16 = 316 // RFC5477, RFC7133
	IEID_MPLS_PAYLOAD_PACKET_SECTION                uint16 = 317 // RFC5477, RFC7133
	IEID_SELECTOR_ID_TOTAL_PKTS_OBSERVED            uint16 = 317 // RFC5477
	IEID_SELECTOR_ID_TOTAL_PKTS_SELECTED            uint16 = 318 // RFC5477
	IEID_ABSOLUTE_ERROR                             uint16 = 320 // RFC5477
	IEID_RELATIVE_ERROR                             uint16 = 321 // RFC5477
	IEID_OBSERVATION_TIME_SECONDS                   uint16 = 322 // RFC5477
	IEID_OBSERVATION_TIME_MILLI_SECONDS             uint16 = 323 // RFC5477
	IEID_OBSERVATION_TIME_MICRO_SECONDS             uint16 = 324 // RFC5477
	IEID_OBSERVATION_TIME_NANO_SECONDS              uint16 = 325 // RFC5477
	IEID_DIGEST_HASH_VALUE                          uint16 = 326 // RFC5477
	IEID_HASH_IP_PAYLOAD_OFFSET                     uint16 = 327 // RFC5477
	IEID_HASH_IP_PAYLOAD_SIZE                       uint16 = 328 // RFC5477
	IEID_HASH_OUTPUT_RANGE_MIN                      uint16 = 329 // RFC5477
	IEID_HASH_OUTPUT_RANGE_MAX                      uint16 = 330 // RFC5477
	IEID_HASH_SELECTED_RANGE_MIN                    uint16 = 331 // RFC5477
	IEID_HASH_SELECTED_RANGE_MAX                    uint16 = 332 // RFC5477
	IEID_HASH_DIGEST_OUTPUT                         uint16 = 333 // RFC5477
	IEID_HASH_INITIALISATION_VALUE                  uint16 = 334 // RFC5477
	IEID_SELECTOR_NAME                              uint16 = 335 // ipfix-iana_at_cisco.com
	IEID_UPPER_CI_LIMIT                             uint16 = 336 // RFC5477
	IEID_LOWER_CI_LIMIT                             uint16 = 337 // RFC5477
	IEID_CONFIDENCE_LEVEL                           uint16 = 338 // RFC5477
	IEID_INFORMATION_ELEMENT_DATA_TYPE              uint16 = 339 // RFC5610
	IEID_INFORMATION_ELEMENT_DESCRIPTION            uint16 = 340 // RFC5610
	IEID_INFORMATION_ELEMENT_NAME                   uint16 = 341 // RFC5610
	IEID_INFORMATION_ELEMENT_RANGE_BEGIN            uint16 = 342 // RFC5610
	IEID_INFORMATION_ELEMENT_RANGE_END              uint16 = 343 // RFC5610
	IEID_INFORMATION_ELEMENT_SEMANTICS              uint16 = 344 // RFC5610
	IEID_INFORMATION_ELEMENT_UNITS                  uint16 = 345 // RFC5610
	IEID_PRIVATE_ENTERPRISE_NUMBER                  uint16 = 346 // RFC5610
	IEID_VIRTUAL_STATION_INTERFACE_ID               uint16 = 347 // ipfix-iana_at_cisco.com
	IEID_VIRTUAL_STATION_INTERFACE_NAME             uint16 = 348 // ipfix-iana_at_cisco.com
	IEID_VIRTUAL_STATION_UUID                       uint16 = 349 // ipfix-iana_at_cisco.com
	IEID_VIRTUAL_STATION_NAME                       uint16 = 350 // ipfix-iana_at_cisco.com
	IEID_LAYER2_SEGMENT_ID                          uint16 = 351 // ipfix-iana_at_cisco.com
	IEID_LAYER2_OCTET_DELTA_COUNT                   uint16 = 352 // ipfix-iana_at_cisco.com
	IEID_LAYER2_OUCET_TOTAL_COUNT                   uint16 = 353 // ipfix-iana_at_cisco.com
	IEID_INGRESS_UNICAST_PACKET_TOTAL_COUNT         uint16 = 354 // ipfix-iana_at_cisco.com
	IEID_INGRESS_MULTICAST_PACKET_TOTAL_COUNT       uint16 = 355 // ipfix-iana_at_cisco.com
	IEID_INGRESS_BROADCAST_PACKET_TOTAL_COUNT       uint16 = 356 // ipfix-iana_at_cisco.com
	IEID_EGRESS_UNICAST_PACKET_TOTAL_COUNT          uint16 = 357 // ipfix-iana_at_cisco.com
	IEID_EGRESS_BROADCAST_PACKET_TOTAL_COUNT        uint16 = 358 // ipfix-iana_at_cisco.com
	IEID_MONITORING_INTERVAL_START_MILLI_SECOUNDS   uint16 = 359 // ipfix-iana_at_cisco.com
	IEID_MONITORING_INTERVAL_END_MILLI_SECOUNDS     uint16 = 360 // ipfix-iana_at_cisco.com
	IEID_PORT_RANGE_START                           uint16 = 361 // ipfix-iana_at_cisco.com
	IEID_PORT_RANGE_END                             uint16 = 362 // ipfix-iana_at_cisco.com
	IEID_PORT_RANGE_STEP_SIZE                       uint16 = 363 // ipfix-iana_at_cisco.com
	IEID_PORT_RANGE_NUM_PORTS                       uint16 = 364 // ipfix-iana_at_cisco.com
	IEID_STA_MAC_ADDRESS                            uint16 = 365 // ipfix-iana_at_cisco.com
	IEID_STA_IPV4_ADDRESS                           uint16 = 366 // ipfix-iana_at_cisco.com
	IEID_WTP_MAC_ADDRESS                            uint16 = 367 // ipfix-iana_at_cisco.com
	IEID_INGRESS_INTERFACE_TYPE                     uint16 = 368 // ipfix-iana_at_cisco.com
	IEID_EGRESS_INTERFACE_TYPE                      uint16 = 369 // ipfix-iana_at_cisco.com
	IEID_RTP_SEQUENCE_NUMBER                        uint16 = 370 // ipfix-iana_at_cisco.com
	IEID_USER_NAME                                  uint16 = 371 // ipfix-iana_at_cisco.com
	IEID_APPLICATION_CATEGORY_NAME                  uint16 = 372 // RFC6759
	IEID_APPLICATION_SUB_CATEGORY_NAME              uint16 = 373 // RFC6759
	IEID_APPLICATION_GROUP_NAME                     uint16 = 374 // RFC6759
	IEID_ORIGINAL_FLOWS_PRESENT                     uint16 = 375 // RFC7015
	IEID_ORIGINAL_FLOWS_INITIATED                   uint16 = 376 // RFC7015
	IEID_ORIGINAL_FLOWS_COMPLETED                   uint16 = 377 // RFC7015
	IEID_DISTINCT_COUNT_OF_SOURCE_IP_ADDRESS        uint16 = 378 // RFC7015
	IEID_DISTINCT_COUNT_OF_DESTINATION_IP_ADDRESS   uint16 = 379 // RFC7015
	IEID_DISTINCT_COUNT_OF_SOURCE_IPV4_ADDRESS      uint16 = 380 // RFC7015
	IEID_DISTINCT_COUNT_OF_DESTINATION_IPV4_ADDRESS uint16 = 381 // RFC7015
	IEID_DISTINCT_COUNT_OF_SOURCE_IPV6_ADDRESS      uint16 = 382 // RFC7015
	IEID_DISTINCT_COUNT_OF_DESTINATION_IPV6_ADDRESS uint16 = 383 // RFC7015
	IEID_VALUE_DISTRIBUTION_METHOD                  uint16 = 384 // RFC7015
	IEID_RFC3550_JITTER_MILLISECONDS                uint16 = 385 // ipfix-iana_at_cisco.com
	IEID_RFC3550_JITTER_MICROSECONDS                uint16 = 386 // ipfix-iana_at_cisco.com
	IEID_RFC3550_JITTER_NANOSECONDS                 uint16 = 387 // ipfix-iana_at_cisco.com
	IEID_DOT1Q_DEI                                  uint16 = 388 // Yaakov_J_Stein
	IEID_DOT1Q_CUSTOMER_DEI                         uint16 = 389 // Yaakov_J_Stein
	IEID_FLOW_SELECTOR_ALGORITHM                    uint16 = 390 // RFC7014
	IEID_FLOW_SELECTED_OCTET_DELTA_COUNT            uint16 = 391 // RFC7014
	IEID_FLOW_SELECTED_PACKET_DELTA_COUNT           uint16 = 392 // RFC7014
	IEID_FLOW_SELECTED_FLOW_DELTA_COUNT             uint16 = 393 // RFC7014
	IEID_SELECTOR_ID_TOTAL_FLOWS_OBSERVED           uint16 = 394 // RFC7014
	IEID_SELECTOR_ID_TOTAL_FLOWS_SELECTED           uint16 = 395 // RFC7014
	IEID_SAMPLING_FLOW_INTERVAL                     uint16 = 396 // RFC7014
	IEID_SAMPLING_FLOW_SPACING                      uint16 = 397 // RFC7014
	IEID_FLOW_SAMPLING_TIME_INTERVAL                uint16 = 398 // RFC7014
	IEID_FLOW_SAMPLING_TIME_SPACING                 uint16 = 399 // RFC7014
	IEID_HASH_FLOW_DOMAIN                           uint16 = 400 // RFC7014
	IEID_TRANSPORT_OCTET_DELTA_COUNT                uint16 = 401 // Brian Trammell
	IEID_TRANSPORT_PACKET_DELTA_COUNT               uint16 = 402 // Brian Trammell
	IEID_ORIGINAL_EXPORTER_IPV4_ADDRESS             uint16 = 403 // RFC7119
	IEID_ORIGINAL_EXPORTER_IPV6_ADDRESS             uint16 = 404 // RFC7119
	IEID_ORIGINAL_OBSERVATION_DOMAIN_ID             uint16 = 405 // RFC7119
	IEID_INTERMEDIATE_PROCESS_ID                    uint16 = 406 // RFC7119
	IEID_IGNORED_DATA_RECORD_TOTAL_COUNT            uint16 = 407 // RFC7119
	IEID_DATA_LINK_FRAME_TYPE                       uint16 = 408 // RFC7133
	IEID_SECTION_OFFSET                             uint16 = 409 // RFC7133
	IEID_SECTION_EXPORTED_OCTETS                    uint16 = 410 // RFC7133
	IEID_DOT1Q_SERVICE_INSTANCE_TAG                 uint16 = 411 // RFC7133
	IEID_DOT1Q_SERVICE_INSTANCE_ID                  uint16 = 412 // RFC7133
	IEID_DOT1Q_SERVICE_INSTANCE_PRIORITY            uint16 = 413 // RFC7133
	IEID_DOT1Q_CUSTOMER_SOURCE_MAC_ADDRESS          uint16 = 414 // RFC7133
	IEID_DOT1Q_CUSTOMER_DESTINATION_MAC_ADDRESS     uint16 = 415 // RFC7133
	// 416: Deprecated
	IEID_POST_LAYER2_OCTET_DELTA_COUNT       uint16 = 417 // RFC7133
	IEID_POST_MCAST_LAYER2_OCTET_DELTA_COUNT uint16 = 418 // RFC7133
	// 419: Deprecated
	IEID_POST_LAYER2_OCTET_TOTAL_COUNT                uint16 = 420 // RFC7133
	IEID_POST_MCAST_LAYER2_OCTET_TOTAL_COUNT          uint16 = 421 // RFC7133
	IEID_MINIMUM_LAYER2_TOTAL_LENGTH                  uint16 = 422 // RFC7133
	IEID_MAXIMUM_LAYER2_TOTAL_LENGTH                  uint16 = 423 // RFC7133
	IEID_DROPPED_LAYER2_OCTET_DELTA_COUNT             uint16 = 424 // RFC7133
	IEID_DROPPED_LAYER2_OCTET_TOTAL_COUNT             uint16 = 425 // RFC7133
	IEID_IGNORED_LAYER2_OCTET_TOTAL_COUNT             uint16 = 426 // RFC7133
	IEID_NOT_SENT_LAYER2_OCTET_TOTAL_COUNT            uint16 = 427 // RFC7133
	IEID_LAYER2_OCTET_DELTA_SUM_OF_SQUARES            uint16 = 428 // RFC7133
	IDID_LAYER2_OCTET_TOTAL_SUM_OF_SQUARES            uint16 = 429 // RFC7133
	IEID_LAYER2_FRAME_DELTA_COUNT                     uint16 = 430 // ipfix-iana_at_cisco.com
	IEID_LAYER2_FRAME_TOTAL_COUNT                     uint16 = 431 // ipfix-iana_at_cisco.com
	IEID_PSEUDOWIRE_DESTINATION_IPV4_ADDRESS          uint16 = 432 // ipfix-iana_at_cisco.com
	IEID_IGNORED_LAYER2_FRAME_TOTAL_COUNT             uint16 = 433 // ipfix-iana_at_cisco.com
	IEID_MIB_OBJECT_VALUE_INTEGER                     uint16 = 434 // RFC8038
	IEID_MIB_OBJECT_VALUE_OCTET_STRING                uint16 = 435 // RFC8038
	IEID_MIB_OBJECT_VALUE_OID                         uint16 = 436 // RFC8038
	IEID_MIB_OBJECT_VALUE_BITS                        uint16 = 437 // RFC8038
	IEID_MIB_OBJECT_VALUE_IP_ADDRESS                  uint16 = 438 // RFC8038
	IEID_MIB_OBJECT_VALUE_COUNTER                     uint16 = 439 // RFC8038
	IEID_MIB_OBJECT_VALUE_GAUGE                       uint16 = 440 // RFC8038
	IEID_MIB_OBJECT_VALUE_TIME_TICKS                  uint16 = 441 // RFC8038
	IEID_MIB_OBJECT_VALUE_UNSIGNED                    uint16 = 442 // RFC8038
	IEID_MIB_OBJECT_VALUE_TABLE                       uint16 = 443 // RFC8038
	IEID_MIB_OBJECT_VALUE_ROW                         uint16 = 444 // RFC8038
	IEID_MIB_OBJECT_IDENTIFIER                        uint16 = 445 // RFC8038
	IEID_MIB_SUB_IDENTIFIER                           uint16 = 446 // RFC8038
	IEID_MIB_INDEX_INDICATOR                          uint16 = 447 // RFC8038
	IEID_MIB_CAPTURE_TIME_SEMICOLONS                  uint16 = 448 // RFC8038
	IEID_MIB_CONTEXT_ENGINE_ID                        uint16 = 449 // RFC8038
	IEID_MIB_CONTEXT_NAME                             uint16 = 450 // RFC8038
	IEID_MIB_OBJECT_NAME                              uint16 = 451 // RFC8038
	IEID_MIB_OBJECT_DESCRIPTION                       uint16 = 452 // RFC8038
	IEID_MIB_OBJECT_SYNTAX                            uint16 = 453 // RFC8038
	IEID_MIB_MODULE_NAME                              uint16 = 454 // RFC8038
	IEID_MOBILE_IMSI                                  uint16 = 455 // ipfix-iana_at_cisco.com
	IEID_MOBILE_MSISDN                                uint16 = 456 // ipfix-iana_at_cisco.com
	IEID_HTTP_STATUS_CODE                             uint16 = 457 // Andrew_Feren
	IEID_SOURCE_TRANSPORT_PORTS_LIMIT                 uint16 = 458 // RFC8045, RFC Errata 5009
	IEID_HTTP_REQUEST_METHOD                          uint16 = 459 // Felix_Erlacher
	IEID_HTTP_REQUEST_HOST                            uint16 = 460 // Felix_Erlacher
	IEID_HTTP_REQUEST_TARGET                          uint16 = 461 // Felix_Erlacher
	IEID_HTTP_MESSAGE_VERSION                         uint16 = 462 // Felix_Erlacher
	IEID_NAT_INSTANCE_ID                              uint16 = 463 // RFC8158
	IEID_INTERNAL_ADDRESS_REALM                       uint16 = 464 // RFC8158
	IEID_EXTERNAL_ADDRESS_REALM                       uint16 = 465 // RFC8158
	IEID_NAT_QUOTA_EXCEEDED_EVENT                     uint16 = 466 // RFC8158
	IEID_NAT_THRESHOLD_EVENT                          uint16 = 467 // RFC8158
	IEID_HTTP_USER_AGENT                              uint16 = 468 // Andrew_Feren
	IEID_HTTP_CONTENT_TYPE                            uint16 = 469 // Andrew_Feren
	IEID_HTTP_REASON_PHRASE                           uint16 = 470 // Felix_Erlacher
	IEID_MAX_SESSION_ENTRIES                          uint16 = 471 // RFC8158
	IEID_MAX_BIB_ENTRIES                              uint16 = 472 // RFC8158
	IEID_MAX_ENTRIES_PER_USER                         uint16 = 473 // RFC8158
	IEID_MAX_SUBSCRIBERS                              uint16 = 474 // RFC8158
	IEID_MAX_FRAGMENTS_PENDING_REASSEMBLY             uint16 = 475 // RFC8158
	IEID_ADDRESS_POOL_HIGH_THRESHOLD                  uint16 = 476 // RFC8158
	IEID_ADDRESS_POOL_LOW_THRESHOLD                   uint16 = 477 // RFC8158
	IEID_ADDRESS_POOL_MAPPING_HIGH_THRESHOLD          uint16 = 478 // RFC8158
	IEID_ADDRESS_POOL_MAPPING_LOW_THRESHOLD           uint16 = 479 // RFC8158
	IEID_ADDRESS_POOL_MAPPING_PER_USER_HIGH_THRESHOLD uint16 = 480 // RFC8158
	IEID_GLOBAL_ADDRESS_MAPPING_HIGH_THRESHOLD        uint16 = 481 // RFC8158
	IEID_VPN_IDENTIFIER                               uint16 = 482 // ipfix-iana_at_cisco.com
	IEID_BGP_COMMUNITY                                uint16 = 483 // RFC8549
	IEID_BGP_SOURCE_COMMUNITY_LIST                    uint16 = 484 // RFC8549
	IEID_BGP_DESTINATION_COMMUNITY_LIST               uint16 = 485 // RFC8549
	IEID_BGP_EXTENDED_COMMUNITY                       uint16 = 486 // RFC8549
	IEID_BGP_SOURCE_EXTENDED_COMMUNITY_LIST           uint16 = 487 // RFC8549
	IEID_BGP_DESTINATION_EXTENDED_COMMUNITY_LIST      uint16 = 488 // RFC8549
	IEID_BGP_LARGE_COMMUNITY                          uint16 = 489 // RFC8549
	IEID_BGP_SOURCE_LARGE_COMMUNITY_LIST              uint16 = 490 // RFC8549
	IEID_BGP_DESTINATION_LARGE_COMMUNITY_LIST         uint16 = 491 // RFC8549
	IEID_SRH_FLAGS_IPV6                               uint16 = 492 // draft-ietf-opsawg-ipfix-srv6-srh
	IEID_SRH_TAG_IPV6                                 uint16 = 493 // draft-ietf-opsawg-ipfix-srv6-srh
	IEID_SRH_SEGMENT_IPV6                             uint16 = 494 // draft-ietf-opsawg-ipfix-srv6-srh
	IEID_SRH_ACTIVE_SEGMENT_IPV6                      uint16 = 495 // draft-ietf-opsawg-ipfix-srv6-srh
	IEID_SRH_SEGMENT_IPV6_BASIC_LIST                  uint16 = 496 // draft-ietf-opsawg-ipfix-srv6-srh
	IEID_SRH_SEGMENT_IPV6_LIST_SECTION                uint16 = 497 // draft-ietf-opsawg-ipfix-srv6-srh
	IEID_SRH_SEGMENT_IPV6_LEFT                        uint16 = 498 // draft-ietf-opsawg-ipfix-srv6-srh
	IEID_SRH_IPV6_SECTION                             uint16 = 499 // draft-ietf-opsawg-ipfix-srv6-srh
	IEID_SRH_IPV6_ACTIVE_SEGMENT_TYPE                 uint16 = 500 // draft-ietf-opsawg-ipfix-srv6-srh
	IEID_SRH_SEGMENT_IPV6_LOCATOR_LENGTH              uint16 = 501 // draft-ietf-opsawg-ipfix-srv6-srh
	IEID_SRH_SEGMENT_IPV6_ENDPOINT_BEHAVIOR           uint16 = 502 // draft-ietf-opsawg-ipfix-srv6-srh
	// 503-520 Unassigned
	IEID_PATH_DELAY_MEAN_DALTA_MICROSECONDS uint16 = 521 // draft-ietf-opsawg-ipfix-on-path-telemetry (not yet allocated by IANA)
	IEID_PATH_DELAY_MEAN_DALTA_NANOSECONDS  uint16 = 522 // draft-ietf-opsawg-ipfix-on-path-telemetry (not yet allocated by IANA)
	IEID_PATH_DELAY_MIN_DALTA_MICROSECONDS  uint16 = 523 // draft-ietf-opsawg-ipfix-on-path-telemetry (not yet allocated by IANA)
	IEID_PATH_DELAY_MIN_DALTA_NANOSECONDS   uint16 = 524 // draft-ietf-opsawg-ipfix-on-path-telemetry (not yet allocated by IANA)
	IEID_PATH_DELAY_MAX_DALTA_MICROSECONDS  uint16 = 525 // draft-ietf-opsawg-ipfix-on-path-telemetry (not yet allocated by IANA)
	IEID_PATH_DELAY_MAX_DALTA_NANOSECONDS   uint16 = 526 // draft-ietf-opsawg-ipfix-on-path-telemetry (not yet allocated by IANA)
	IEID_PATH_DELAY_SUM_DALTA_MICROSECONDS  uint16 = 527 // draft-ietf-opsawg-ipfix-on-path-telemetry (not yet allocated by IANA)
	IEID_PATH_DELAY_SUM_DALTA_NANOSECONDS   uint16 = 528 // draft-ietf-opsawg-ipfix-on-path-telemetry (not yet allocated by IANA)
)
