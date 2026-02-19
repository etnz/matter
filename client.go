package matter

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/tom-code/gomat"
)

// Client is a Matter client.
type Client struct {
	// Transport specifies the mechanism by which individual requests are made.
	// If nil, a new ephemeral net.PacketConn is created for each request.
	Transport net.PacketConn

	// Channels for internal loop communication

	incoming   chan exchange
	register   chan clientExchange
	unregister chan clientExchange
	outgoing   chan exchange

	initOnce sync.Once
}

// attache together an exchange and a response chan.
type clientExchange struct {
	exchange
	ch chan exchange
}

func (c *Client) init() {
	c.initOnce.Do(func() {
		c.incoming = make(chan exchange)
		c.register = make(chan clientExchange)
		c.unregister = make(chan clientExchange)
		c.outgoing = make(chan exchange)

		if c.Transport == nil {
			var err error
			c.Transport, err = net.ListenPacket("udp", ":0")
			if err != nil {
				panic(fmt.Sprintf("failed to create default transport: %v", err))
			}
		}

		go c.listenLoop()
		go c.managerLoop()
		go c.writerLoop()
	})
}

func (c *Client) listenLoop() {
	buf := make([]byte, 4096)
	for {
		n, addr, err := c.Transport.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		hdr, payload := decodeProtocolMessageHeader(pkt)
		x := exchange{
			RemoteAddr:            addr,
			ProtocolMessageHeader: hdr,
			Payload:               payload,
			reliable:              (hdr.ExchangeFlags & FlagReliable) != 0,
		}

		c.incoming <- x
	}
}

func (c *Client) managerLoop() {
	exchanges := make(map[uint16]chan exchange)
	for {
		select {
		case x := <-c.register:
			exchanges[x.ProtocolMessageHeader.ExchangeID] = x.ch
		case x := <-c.unregister:
			delete(exchanges, x.ProtocolMessageHeader.ExchangeID)
		case x := <-c.incoming:
			if ch, ok := exchanges[x.ProtocolMessageHeader.ExchangeID]; ok {
				select {
				case ch <- x:
				default:
				}
			}
		}
	}
}

func (c *Client) writerLoop() {
	for x := range c.outgoing {
		x.writeTo(c.Transport)
	}
}

// Request sends a raw message to the address and waits for a response.
func (c *Client) Request(ctx context.Context, addr net.Addr, proto gomat.ProtocolId, opcode gomat.Opcode, payload []byte) (gomat.ProtocolId, gomat.Opcode, []byte, error) {
	// Make sure the client is initialized once.
	c.init()

	// Create an unique exchange context for this request.
	x := clientExchange{
		exchange: exchange{
			RemoteAddr: addr,
			ProtocolMessageHeader: ProtocolMessageHeader{
				ExchangeFlags: FlagReliable,
				Opcode:        opcode,
				ProtocolId:    proto,
				ExchangeID:    uint16(rand.Intn(0xffff)),
			},
			Payload:  payload,
			reliable: true,
		},
		ch: make(chan exchange, 1),
	}

	// Register the response chan to receive responses related to the exchangeID.
	select {
	case c.register <- x:
	case <-ctx.Done():
		return 0, 0, nil, ctx.Err()
	}
	// and deregister it, afterwards.
	defer func() {
		select {
		case c.unregister <- x:
		case <-time.After(100 * time.Millisecond):
		}
	}()

	// Wait for response loop, implementing the MRP spec.
	var sawAck bool
	// MRP Parameters (simplified)
	retryInterval := 200 * time.Millisecond
	maxRetries := 5

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Send if we haven't received an ACK yet
		if !sawAck {
			select {
			// pass the request to the sending layer 1.
			case c.outgoing <- x.exchange:
			case <-ctx.Done():
				return 0, 0, nil, ctx.Err()
			}
		}

		// Determine timeout
		timeout := retryInterval * (1 << attempt)
		if sawAck {
			// If we already saw an ACK, we are just waiting for the application response.
			timeout = 10 * time.Second
		}
		// Add Jitter: t + rand(0, t * 0.1)
		if timeout > 0 {
			timeout += time.Duration(rand.Int63n(int64(timeout) / 10))
		}

		// Wait on the next Responsem either an empty ack, or an actual message with a piggybacking ack.
		select {
		case resp := <-x.ch:

			// Check for Standalone ACK
			// ProtocolId is SecureChannel and Opcode is ACK
			if resp.IsAck() {
				sawAck = true
				// Stop retransmitting, but continue loop to wait for app response
				continue
			}
			// This was not a standalone ACK but a real message, we acknowledge that it was received if requested.
			if (resp.ProtocolMessageHeader.ExchangeFlags & FlagReliable) != 0 {
				// Ack the response.
				ack := x.ack(resp.ProtocolMessageHeader.ExchangeID)
				select {
				case c.outgoing <- ack:
				default:
					log.Printf("failed to queue ack")
				}
			}
			// We simply return the response whatever that is.
			// Maybe according to the spec we should test that protocol ID and OpCode validity.

			// Check Piggybacked ACK
			if (resp.ProtocolMessageHeader.ExchangeFlags & FlagAck) != 0 {
				// We could verify resp.ProtocolMessageHeader.AckCounter == msgCounter here
			}
			return resp.ProtocolMessageHeader.ProtocolId, resp.ProtocolMessageHeader.Opcode, resp.Payload, nil

		case <-time.After(timeout):
			if sawAck {
				// If we saw ACK but timed out waiting for response, that's an error
				return 0, 0, nil, fmt.Errorf("timeout waiting for response after ACK")
			}
			// Retry loop
			continue

		case <-ctx.Done():
			return 0, 0, nil, ctx.Err()
		}
	}

	return 0, 0, nil, fmt.Errorf("max retries exceeded")
}
