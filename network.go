package matter

import (
	"log/slog"
	"net"
)

// network moves matter messages around.
type network struct {
	logger *slog.Logger
}

func (s *network) readLoop(pc net.PacketConn, inbound chan<- packet) error {

	buf := make([]byte, 4096) // Standard MTU safe buffer

	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			close(inbound)
			return err
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		msg := packet{
			addr:    addr,
			payload: payload,
		}
		s.logger.Debug("net read", "msg", msg)

		// block or drop? should be drop
		select {
		case inbound <- msg:
		default:
			s.logger.Warn("dropped message", "addr", msg.addr)
		}
	}
}

func (s *network) writeLoop(pc net.PacketConn, input <-chan packet) {
	for msg := range input {
		s.logger.Debug("net write", "msg", msg)
		if _, err := msg.WriteTo(pc); err != nil {
			s.logger.Warn("failed to write", "error", err)
		}
	}
}

type connection struct {
	pc       net.PacketConn
	inbound  chan packet
	outbound chan packet
}

func (s *network) new(pc net.PacketConn) *connection {
	conn := &connection{
		pc:       pc,
		inbound:  make(chan packet, 10),
		outbound: make(chan packet, 10),
	}
	go s.readLoop(pc, conn.inbound)
	go s.writeLoop(pc, conn.outbound)
	return conn
}

func (c *connection) close() {
	close(c.inbound)
	close(c.outbound)
}
