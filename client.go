package matter

import (
	"context"
	"net"

	"github.com/tom-code/gomat"
)

// Client is a Matter client.
type Client struct {
	// Transport specifies the mechanism by which individual requests are made.
	// If nil, a new ephemeral net.PacketConn is created for each request.
	Transport net.PacketConn
}

// Request sends a raw message to the address and waits for a response.
func (c *Client) Request(ctx context.Context, addr net.Addr, proto gomat.ProtocolId, opcode gomat.Opcode, payload []byte) (gomat.ProtocolId, gomat.Opcode, []byte, error) {
	conn := c.Transport
	if conn == nil {
		var err error
		conn, err = net.ListenPacket("udp", ":0")
		if err != nil {
			return 0, 0, nil, err
		}
		defer conn.Close()
	}

	// TODO layer 2 parameters
	p := ProtocolMessageHeader{
		ExchangeFlags: 0,
		Opcode:        opcode,
		ProtocolId:    proto,
	}

	ec := ExchangeContext{
		Context:               ctx,
		conn:                  conn,
		RemoteAddr:            addr,
		ProtocolMessageHeader: p,
		Payload:               payload,
	}
	if _, err := ec.send(p, payload); err != nil {
		return 0, 0, nil, err
	}

	// Wait for response
	buf := make([]byte, 4096)

	// Check context before blocking read
	if err := ctx.Err(); err != nil {
		return 0, 0, nil, err
	}

	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		if ctx.Err() != nil {
			return 0, 0, nil, ctx.Err()
		}
		return 0, 0, nil, err
	}

	// TODO: if required: check for ACK in the response
	// If none return an error
	// if empty ack message wait for the "real" message response (using MRP spec)
	// if piggybacked, return the "real" response.

	// Decode Response
	p, payload = decodeProtocolMessageHeader(buf[:n])
	return p.ProtocolId, p.Opcode, payload, nil
}
