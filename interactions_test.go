package matter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

func setupInteractionTest(t *testing.T) (*Client, *Server) {
	t.Helper()
	network := newMockNetwork()

	// 1. Setup Server
	serverAddr := "server:5540"
	serverConn := network.listenPacket(serverAddr)

	cm, err := NewGeneratedCertificateManager()
	if err != nil {
		t.Fatal(err)
	}
	ipk := make([]byte, 16)
	fabric := NewFabric(1, 1, ipk, cm)
	server := &Server{
		Fabric: fabric,
		Addr:   serverAddr,
	}

	// Run server in goroutine
	go func() {
		if err := server.Serve(serverConn); err != nil && !errors.Is(err, net.ErrClosed) && err.Error() != "server closed" {
			t.Errorf("server error: %v", err)
		}
	}()

	// 2. Setup Client
	clientConn := network.listenPacket("client:1234")
	clientFabric := NewFabric(1, 2, ipk, cm)
	client := &Client{
		Transport:   clientConn,
		PeerAddress: &mockAddr{serverAddr},
		Fabric:      clientFabric,
	}

	return client, server
}

func TestInteraction_ReadRequest_PingPong(t *testing.T) {
	client, server := setupInteractionTest(t)

	ping := uint64(1234)
	pong := uint8(123)
	// Client Request to send a ping
	req := ReadRequestMessage{
		AttributeRequests: []AttributePathIB{
			{
				Node: &ping,
			},
		},
	}
	// Setup Server Handler
	server.ReadHandler = func(ctx context.Context, req ReadRequestMessage) (ReportDataMessage, error) {

		// Verify PING in req.RawPayload
		val := req.AttributeRequests[0].Node
		if val == nil || *val != ping {
			t.Errorf("server received ReadRequest with AttributeRequests %v want %q", val, ping)
			return ReportDataMessage{}, fmt.Errorf("expected PING, got %v", val)
		}

		// Send back a PONG
		// AttributeReports is Tag 1.
		// We put OctetString(1, "PONG") inside.
		return ReportDataMessage{
			AttributeReports: []AttributeReportIB{
				{AttributeStatus: &AttributeStatusIB{
					Status: StatusIB{Status: &pong},
				},
				},
			},
		}, nil
	}

	resp, err := client.Read(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Verify PONG
	val := resp.AttributeReports[0].AttributeStatus.Status.Status
	if val == nil || *val != pong {
		t.Errorf("Expected PONG, got %v", val)
	}

}
