package matter

import (
	"context"
	"net"
)

// Client is a Matter client.
type Client struct {
	// Transport specifies the mechanism by which individual requests are made.
	// If nil, a new ephemeral net.PacketConn is created for each request.
	Transport net.PacketConn
}

// Send sends a raw message to the address and waits for a response.
func (c *Client) Send(ctx context.Context, addr net.Addr, msg []byte) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	conn := c.Transport
	if conn == nil {
		var err error
		conn, err = net.ListenPacket("udp", ":0")
		if err != nil {
			return nil, err
		}
		defer conn.Close()
	}

	if _, err := conn.WriteTo(msg, addr); err != nil {
		return nil, err
	}

	// Wait for response
	buf := make([]byte, 4096)

	// Check context before blocking read
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}
