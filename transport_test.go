package matter

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// TestPhase1_PingPong verifies the Phase 1 requirement:
// The Client sends "PING", and the Server successfully triggers the handler and routes "PONG" back.
func TestPhase1_PingPong(t *testing.T) {
	network := newMockNetwork()

	// 1. Setup Server
	serverAddr := "server:5540"
	serverConn := network.listenPacket(serverAddr)
	mux := NewServeMux()
	mux.HandleFunc(0, 0xFE, func(ctx *ExchangeContext) {
		// Handler replies PONG
		if _, err := ctx.Response(0, 0xFF, []byte("PONG")); err != nil {
			t.Errorf("failed to respond: %v", err)
		}
	})

	server := &Server{
		Handler: mux,
	}

	// Run server in goroutine
	go func() {
		if err := server.Serve(serverConn); err != nil && err.Error() != "server closed" {
			t.Errorf("server error: %v", err)
		}
	}()
	defer server.Shutdown(context.Background())

	// 2. Setup Client
	clientConn := network.listenPacket("client:1234")
	client := &Client{
		Transport: clientConn,
	}

	// 3. Execute Test
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, resp, err := client.Request(ctx, &mockAddr{serverAddr}, 0, 0xFE, []byte("PING"))
	if err != nil {
		t.Fatalf("client send failed: %v", err)
	}

	if !bytes.Equal(resp, []byte("PONG")) {
		t.Errorf("got %s, want PONG", string(resp))
	}
}

// --- Mock Transport Implementation ---

type packet struct {
	from net.Addr
	data []byte
}

// MockPacketConn implements net.PacketConn using channels.
type MockPacketConn struct {
	addr         net.Addr
	readCh       chan packet
	network      *mockNetwork
	closed       bool
	mu           sync.Mutex
	readDeadline time.Time
}

func (c *MockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var timeout <-chan time.Time
	c.mu.Lock()
	if !c.readDeadline.IsZero() {
		d := time.Until(c.readDeadline)
		if d <= 0 {
			c.mu.Unlock()
			return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: context.DeadlineExceeded}
		}
		timeout = time.After(d)
	}
	c.mu.Unlock()

	select {
	case pkt, ok := <-c.readCh:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n = copy(p, pkt.data)
		return n, pkt.from, nil
	case <-timeout:
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: context.DeadlineExceeded}
	}
}

func (c *MockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.mu.Unlock()

	// Send to network
	data := make([]byte, len(p))
	copy(data, p)
	c.network.route(c.addr, addr, data)
	return len(p), nil
}

func (c *MockPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.readCh)
		c.network.unbind(c.addr)
	}
	return nil
}

func (c *MockPacketConn) LocalAddr() net.Addr { return c.addr }
func (c *MockPacketConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}
func (c *MockPacketConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *MockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// mockNetwork simulates the UDP network.
type mockNetwork struct {
	mu    sync.Mutex
	conns map[string]*MockPacketConn
}

func newMockNetwork() *mockNetwork {
	return &mockNetwork{
		conns: make(map[string]*MockPacketConn),
	}
}

func (n *mockNetwork) listenPacket(addr string) *MockPacketConn {
	n.mu.Lock()
	defer n.mu.Unlock()

	a := &mockAddr{addr}
	conn := &MockPacketConn{
		addr:    a,
		readCh:  make(chan packet, 100), // Buffered to avoid tight coupling in tests
		network: n,
	}
	n.conns[addr] = conn
	return conn
}

func (n *mockNetwork) route(from, to net.Addr, data []byte) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if target, ok := n.conns[to.String()]; ok {
		// Non-blocking send to avoid deadlocks
		select {
		case target.readCh <- packet{from: from, data: data}:
		default:
		}
	}
}

func (n *mockNetwork) unbind(addr net.Addr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.conns, addr.String())
}

type mockAddr struct{ s string }

func (a *mockAddr) Network() string { return "udp" }
func (a *mockAddr) String() string  { return a.s }
