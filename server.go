package matter

import (
	"context"
	"errors"
	"net"
	"sync"
)

// Handler responds to an incoming Matter request.
type Handler interface {
	Serve(ctx *ExchangeContext)
}

// HandlerFunc is an adapter to allow the use of ordinary functions as Matter handlers.
type HandlerFunc func(ctx *ExchangeContext)

// Serve calls f(ctx).
func (f HandlerFunc) Serve(ctx *ExchangeContext) {
	f(ctx)
}

// ExchangeContext holds the context for the current exchange.
// It provides access to the incoming request and a way to send a response.
type ExchangeContext struct {
	context.Context
	conn       net.PacketConn
	RemoteAddr net.Addr
	Request    []byte
}

// Response sends data back to the remote peer.
func (c *ExchangeContext) Response(data []byte) (int, error) {
	return c.conn.WriteTo(data, c.RemoteAddr)
}

// Server defines parameters for running a Matter server.
type Server struct {
	// Addr optionally specifies the UDP address for the server to listen on,
	// in the form "host:port". If empty, ":5540" (standard Matter port) is used.
	Addr string

	// Handler to invoke, ServeMux is used if nil.
	Handler Handler

	// BaseContext optionally specifies a function that returns the base context
	// for incoming requests on this server.
	BaseContext func(net.Addr) context.Context

	mu         sync.Mutex
	activeConn map[net.PacketConn]struct{}
	inShutdown bool
}

// ListenAndServe listens on the UDP network address s.Addr and then calls Serve.
func (s *Server) ListenAndServe() error {
	addr := s.Addr
	if addr == "" {
		addr = ":5540"
	}
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	return s.Serve(conn)
}

// Serve accepts incoming packets on the PacketConn and creates a new service goroutine for each.
func (s *Server) Serve(pc net.PacketConn) error {
	s.trackConn(pc, true)
	defer s.trackConn(pc, false)

	buf := make([]byte, 4096) // Standard MTU safe buffer
	for {
		if s.shuttingDown() {
			return errors.New("server closed")
		}

		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if s.shuttingDown() {
				return errors.New("server closed")
			}
			return err
		}

		// Copy payload as buf is reused
		payload := make([]byte, n)
		copy(payload, buf[:n])

		ctx := context.Background()
		if s.BaseContext != nil {
			ctx = s.BaseContext(addr)
		}

		exch := &ExchangeContext{
			Context:    ctx,
			conn:       pc,
			RemoteAddr: addr,
			Request:    payload,
		}

		handler := s.Handler
		if handler == nil {
			// Default fallback if needed, or panic? For now, assume handler is set.
			continue
		}

		go handler.Serve(exch)
	}
}

func (s *Server) trackConn(c net.PacketConn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeConn == nil {
		s.activeConn = make(map[net.PacketConn]struct{})
	}
	if add {
		s.activeConn[c] = struct{}{}
	} else {
		delete(s.activeConn, c)
	}
}

func (s *Server) shuttingDown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inShutdown
}

// Shutdown gracefully shuts down the server without interrupting any active exchanges.
// For UDP, this primarily means closing the listener to stop accepting new packets.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.inShutdown = true
	s.mu.Unlock()

	// Close all active connections to unblock ReadFrom
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.activeConn {
		c.Close()
	}
	return nil
}
