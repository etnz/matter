package matter

import (
	"bytes"
	"net"

	"github.com/tom-code/gomat"
)

// exchange holds the context required to perform a exchange.
type exchange struct {
	RemoteAddr            net.Addr
	ProtocolMessageHeader ProtocolMessageHeader
	Payload               []byte
	reliable              bool
}

func (c exchange) writeTo(conn net.PacketConn) (int, error) {
	var buf bytes.Buffer
	c.ProtocolMessageHeader.Encode(&buf)
	buf.Write(c.Payload)
	return conn.WriteTo(buf.Bytes(), c.RemoteAddr)
}

// ack return an exchange for ack.
func (c exchange) ack(exchangeID uint16) exchange {
	return exchange{
		RemoteAddr: c.RemoteAddr,
		Payload:    nil,
		reliable:   false,
		ProtocolMessageHeader: ProtocolMessageHeader{
			ExchangeFlags: FlagAck,
			Opcode:        gomat.SEC_CHAN_OPCODE_ACK,
			ProtocolId:    gomat.ProtocolIdSecureChannel,
			ExchangeID:    exchangeID,
			AckCounter:    0,
		},
	}
}

func (c exchange) IsAck() bool {
	return c.ProtocolMessageHeader.ProtocolId == gomat.ProtocolIdSecureChannel && c.ProtocolMessageHeader.Opcode == gomat.SEC_CHAN_OPCODE_ACK
}
