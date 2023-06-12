// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package ipfix

import (
	"encoding/binary"
	"time"
)

const (
	IPFIX_VERSION uint16 = 10
)

type Message struct { // RFC7011 3.
	Version             uint16
	SequenceNumber      uint32
	ObservationDomainID uint32
	Sets                []Set
}

func (m *Message) Serialize() []uint8 {
	buf := make([]uint8, 0)
	version := make([]uint8, 2)
	binary.BigEndian.PutUint16(version, m.Version)
	buf = append(buf, version...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, uint16(m.Len()))
	buf = append(buf, length...)

	exportTime := make([]uint8, 4)
	binary.BigEndian.PutUint32(exportTime, uint32(time.Now().Unix()))
	buf = append(buf, exportTime...)

	sequenceNumber := make([]uint8, 4)
	binary.BigEndian.PutUint32(sequenceNumber, m.SequenceNumber)
	buf = append(buf, sequenceNumber...)

	observationDomainID := make([]uint8, 4)
	binary.BigEndian.PutUint32(observationDomainID, m.ObservationDomainID)
	buf = append(buf, observationDomainID...)

	sets := make([]uint8, 0)
	for _, s := range m.Sets {
		sets = append(sets, s.Serialize()...)
	}
	buf = append(buf, sets...)

	return buf
}

func (m *Message) Len() uint16 {
	headerLen := uint16(16)
	var setsLen uint16
	for _, s := range m.Sets {
		setsLen += s.Len()
	}
	return headerLen + setsLen
}

func NewMessage(seq uint32, obsID uint32, sets []Set) *Message {
	h := &Message{
		Version:             IPFIX_VERSION,
		SequenceNumber:      seq,
		ObservationDomainID: obsID,
		Sets:                sets,
	}
	return h
}

const (
	TEMPLATE_SETS_ID         uint16 = 2 // RFC7011 3.3.2
	OPTIONS_TEMPLATE_SETS_ID uint16 = 3 // RFC7011 3.3.2
)

type Set struct { // RFC7011 3.3.1
	SetID   uint16
	Records []Record
}

func (s *Set) Serialize() []uint8 {
	buf := make([]uint8, 0)
	setID := make([]uint8, 2)
	binary.BigEndian.PutUint16(setID, s.SetID)
	buf = append(buf, setID...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, s.Len())
	buf = append(buf, length...)

	records := make([]uint8, 0)
	for _, r := range s.Records {
		records = append(records, r.Serialize()...)
	}
	buf = append(buf, records...)

	if len(buf)%4 != 0 {
		pad := make([]uint8, 4-len(buf)%4)
		buf = append(buf, pad...)
	}

	return buf
}

func (s *Set) Len() uint16 {
	headerLen := uint16(4)
	var recordsLen uint16
	for _, r := range s.Records {
		recordsLen += r.Len()
	}

	padding := uint16(0)
	l := headerLen + recordsLen
	if l%4 != 0 {
		padding = (4 - l%4)
	}
	return l + padding
}

func NewSet(setID uint16, records []Record) *Set {
	return &Set{
		SetID:   setID,
		Records: records,
	}
}

type FieldSpecifier struct { // RFC7011 3.2
	E                    bool
	InformationElementID uint16
	FieldLength          uint16 // length of data field
	EnterpriseNumber     uint32
}

func (s *FieldSpecifier) Serialize() []uint8 {
	buf := make([]uint8, 0, 8)
	informationElementId := make([]uint8, 2)
	binary.BigEndian.PutUint16(informationElementId, s.InformationElementID)
	if s.E {
		informationElementId[0] = informationElementId[0] | 1<<7
	}
	buf = append(buf, informationElementId...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, s.FieldLength)
	buf = append(buf, length...)
	if s.E {
		enterpriseNumber := make([]uint8, 4)
		binary.BigEndian.PutUint32(enterpriseNumber, s.EnterpriseNumber)
		buf = append(buf, enterpriseNumber...)
	}
	return buf
}

func (s *FieldSpecifier) Len() uint16 {
	if s.E {
		return uint16(8)
	} else {
		return uint16(4)
	}
}

func NewFieldSpecifier(e bool, informationElementID uint16, length uint16, enterpriseNumber uint32) *FieldSpecifier {
	h := &FieldSpecifier{
		E:                    e,
		InformationElementID: informationElementID,
		FieldLength:          length,
	}
	if e {
		h.EnterpriseNumber = enterpriseNumber
	}
	return h
}

type Record interface { // RFC7011 3.4
	Serialize() []uint8
	Len() uint16
}

type TemplateRecord struct { // RFC7011 3.4.1
	TemplateID      uint16
	FieldSpecifiers []FieldSpecifier
}

func (r *TemplateRecord) Serialize() []uint8 {
	buf := make([]uint8, 0)
	templateID := make([]uint8, 2)
	binary.BigEndian.PutUint16(templateID, r.TemplateID)
	buf = append(buf, templateID...)

	fieldCount := make([]uint8, 2)
	binary.BigEndian.PutUint16(fieldCount, uint16(len(r.FieldSpecifiers)))
	buf = append(buf, fieldCount...)

	fieldSpecifiers := make([]uint8, 0)
	for _, fs := range r.FieldSpecifiers {
		fieldSpecifiers = append(fieldSpecifiers, fs.Serialize()...)
	}
	buf = append(buf, fieldSpecifiers...)

	return buf
}

func (r *TemplateRecord) Len() uint16 {
	headerLen := uint16(4)

	var fsLen uint16
	for _, fs := range r.FieldSpecifiers {
		fsLen += fs.Len()
	}

	return headerLen + fsLen
}

func NewTemplateRecord(templateID uint16, fieldSpecifiers []FieldSpecifier) *TemplateRecord {
	return &TemplateRecord{
		TemplateID:      templateID,
		FieldSpecifiers: fieldSpecifiers,
	}
}

type OptionsTemplateRecord struct { // RFC7011 3.4.2.2
	TemplateID      uint16
	ScopeFieldCount uint16
	FieldSpecifiers []FieldSpecifier
}

func (r *OptionsTemplateRecord) Serialize() []uint8 {
	buf := make([]uint8, 0)
	templateID := make([]uint8, 2)
	binary.BigEndian.PutUint16(templateID, r.TemplateID)
	buf = append(buf, templateID...)

	fieldCount := make([]uint8, 2)
	binary.BigEndian.PutUint16(fieldCount, uint16(len(r.FieldSpecifiers)))
	buf = append(buf, fieldCount...)

	scopeFieldCount := make([]uint8, 2)
	binary.BigEndian.PutUint16(fieldCount, r.ScopeFieldCount)
	buf = append(buf, scopeFieldCount...)

	fieldSpecifiers := make([]uint8, 0)
	for _, fs := range r.FieldSpecifiers {
		fieldSpecifiers = append(fieldSpecifiers, fs.Serialize()...)
	}
	buf = append(buf, fieldSpecifiers...)

	return buf
}

func (r *OptionsTemplateRecord) Len() uint16 {
	headerLen := uint16(6)

	var fsLen uint16
	for _, fs := range r.FieldSpecifiers {
		fsLen += fs.Len()
	}

	return headerLen + fsLen
}

func NewOptionTemplateRecord(optionTemplateID uint16, scopeFieldCount uint16, fieldSpecifiers []FieldSpecifier) *OptionsTemplateRecord {
	return &OptionsTemplateRecord{
		TemplateID:      optionTemplateID,
		ScopeFieldCount: scopeFieldCount,
		FieldSpecifiers: fieldSpecifiers,
	}
}

type DataRecord struct { // RFC7011 3.4.3
	FieldValues []FieldValue
}

func (r *DataRecord) Serialize() []uint8 {
	buf := make([]uint8, 0)

	for _, v := range r.FieldValues {
		buf = append(buf, v.Serialize()...)
	}

	return buf

}

func (r *DataRecord) Len() uint16 {
	var fvLen uint16
	for _, v := range r.FieldValues {
		fvLen += v.Len()
	}

	return fvLen
}
