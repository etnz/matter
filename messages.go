package matter

import (
	"bytes"
	"encoding/binary"

	"github.com/tom-code/gomat"
)

type ProtocolMessageHeader struct {
	ExchangeFlags uint8
	Opcode        gomat.Opcode
	ExchangeId    uint16
	ProtocolId    gomat.ProtocolId
	AckCounter    uint32
}

func (m *ProtocolMessageHeader) Encode(data *bytes.Buffer) {
	data.WriteByte(m.ExchangeFlags)
	data.WriteByte(byte(m.Opcode))
	binary.Write(data, binary.LittleEndian, m.ExchangeId)
	binary.Write(data, binary.LittleEndian, m.ProtocolId)
	if (m.ExchangeFlags & 0x02) != 0 {
		binary.Write(data, binary.LittleEndian, m.AckCounter)
	}
}

func (m *ProtocolMessageHeader) Decode(data *bytes.Buffer) {
	m.ExchangeFlags, _ = data.ReadByte()
	opcode, _ := data.ReadByte()
	m.Opcode = gomat.Opcode(opcode)
	binary.Read(data, binary.LittleEndian, &m.ExchangeId)
	binary.Read(data, binary.LittleEndian, &m.ProtocolId)
	if (m.ExchangeFlags & 0x02) != 0 {
		binary.Read(data, binary.LittleEndian, &m.AckCounter)
	}
}

func encodeProtocolMessageHeader(proto ProtocolMessageHeader, payload []byte) []byte {
	var buf bytes.Buffer
	proto.Encode(&buf)
	buf.Write(payload)
	return buf.Bytes()
}

func decodeProtocolMessageHeader(msg []byte) (proto ProtocolMessageHeader, payload []byte) {
	buf := bytes.NewBuffer(msg)
	proto.Decode(buf)
	return proto, buf.Bytes()
}
