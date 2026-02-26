package matter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/etnz/matter/securechannel"
)

func setupInteractionTest(t *testing.T) (*Client, *Server) {
	t.Helper()
	network := newMockNetwork()

	// 1. Setup Server
	serverAddr := "server:5540"
	serverConn := network.listenPacket(serverAddr)

	cm, err := securechannel.NewGeneratedCertificateManager()
	if err != nil {
		t.Fatal(err)
	}
	ipk := make([]byte, 16)
	fabric := securechannel.NewFabric(1, 1, ipk, cm)
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
	clientFabric := securechannel.NewFabric(1, 2, ipk, cm)
	client, err := NewCommissionedClient(clientConn, &mockAddr{serverAddr}, clientFabric)
	if err != nil {
		t.Fatal(err)
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
		if len(req.AttributeRequests) == 0 {
			t.Errorf("server received ReadRequest with no AttributeRequests")
			return ReportDataMessage{}, fmt.Errorf("no AttributeRequests")
		}
		val := req.AttributeRequests[0].Node
		if val == nil || *val != ping {
			t.Errorf("server received ReadRequest with AttributeRequests %v want %q", val, ping)
			return ReportDataMessage{}, fmt.Errorf("expected PING, got %v", val)
		}

		// Send back a PONG
		return ReportDataMessage{
			AttributeReports: []AttributeReportIB{
				{
					AttributeStatus: &AttributeStatusIB{
						Path:   req.AttributeRequests[0],
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
	if len(resp.AttributeReports) == 0 {
		t.Fatalf("client received ReportData with no AttributeReports")
	}
	val := resp.AttributeReports[0].AttributeStatus.Status.Status
	if val == nil || *val != pong {
		t.Errorf("Expected PONG, got %v", val)
	}

}

func TestInteractionMessages_EncodeDecode(t *testing.T) {
	ptrBool := func(b bool) *bool { return &b }
	ptrUint64 := func(u uint64) *uint64 { return &u }
	ptrUint32 := func(u uint32) *uint32 { return &u }
	ptrUint16 := func(u uint16) *uint16 { return &u }
	ptrUint8 := func(u uint8) *uint8 { return &u }

	t.Run("StatusResponseMessage", func(t *testing.T) {
		in := StatusResponseMessage{Status: 0x01}
		encoded := in.Encode().Bytes()
		var out StatusResponseMessage
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("ReadRequestMessage", func(t *testing.T) {
		in := ReadRequestMessage{
			AttributeRequests: []AttributePathIB{
				{Node: ptrUint64(1), Endpoint: ptrUint16(2), Cluster: ptrUint32(3), Attribute: ptrUint32(4)},
			},
			EventRequests: []EventPathIB{
				{Node: ptrUint64(1), Endpoint: ptrUint16(2), Cluster: ptrUint32(3), Event: ptrUint32(5), IsUrgent: ptrBool(true)},
			},
			EventFilters: []EventFilterIB{
				{Node: ptrUint64(1), EventMin: 100},
			},
			FabricFiltered: true,
			DataVersionFilters: []DataVersionFilterIB{
				{Path: ClusterPathIB{Node: ptrUint64(1), Endpoint: ptrUint16(2), Cluster: ptrUint32(3)}, DataVersion: 99},
			},
		}
		encoded := in.Encode().Bytes()
		var out ReadRequestMessage
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("SubscribeRequestMessage", func(t *testing.T) {
		in := SubscribeRequestMessage{
			KeepSubscriptions:  true,
			MinIntervalFloor:   10,
			MaxIntervalCeiling: 100,
			AttributeRequests: []AttributePathIB{
				{Cluster: ptrUint32(3), Attribute: ptrUint32(4)},
			},
			FabricFiltered: true,
		}
		encoded := in.Encode().Bytes()
		var out SubscribeRequestMessage
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("SubscribeResponseMessage", func(t *testing.T) {
		in := SubscribeResponseMessage{
			SubscriptionID: 12345,
			MaxInterval:    100,
		}
		encoded := in.Encode().Bytes()
		var out SubscribeResponseMessage
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("ReportDataMessage", func(t *testing.T) {
		in := ReportDataMessage{
			SubscriptionID: ptrUint32(12345),
			AttributeReports: []AttributeReportIB{
				{
					AttributeData: &AttributeDataIB{
						DataVersion: ptrUint32(1),
						Path:        AttributePathIB{Cluster: ptrUint32(3), Attribute: ptrUint32(4)},
						Data:        uint64(42), // Note: Data is 'any', decoding might produce specific type
					},
				},
			},
			MoreChunkedMessages: true,
			SuppressResponse:    true,
		}
		encoded := in.Encode().Bytes()
		var out ReportDataMessage
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		// DeepEqual might fail on 'Data' type if not careful.
		// tlv.Decode returns uint64 for integers.
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("WriteRequestMessage", func(t *testing.T) {
		in := WriteRequestMessage{
			SuppressResponse: true,
			TimedRequest:     true,
			WriteRequests: []AttributeDataIB{
				{
					Path: AttributePathIB{Cluster: ptrUint32(3), Attribute: ptrUint32(4)},
					Data: true,
				},
			},
			MoreChunkedMessages: false,
		}
		encoded := in.Encode().Bytes()
		var out WriteRequestMessage
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("WriteResponseMessage", func(t *testing.T) {
		in := WriteResponseMessage{
			WriteResponses: []AttributeStatusIB{
				{
					Path:   AttributePathIB{Cluster: ptrUint32(3), Attribute: ptrUint32(4)},
					Status: StatusIB{Status: ptrUint8(0)},
				},
			},
		}
		encoded := in.Encode().Bytes()
		var out WriteResponseMessage
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("InvokeRequestMessage", func(t *testing.T) {
		in := InvokeRequestMessage{
			SuppressResponse: false,
			TimedRequest:     true,
			InvokeRequests: []CommandDataIB{
				{
					Path:   CommandPathIB{EndpointId: ptrUint16(1), ClusterId: ptrUint32(2), CommandId: ptrUint32(3)},
					Fields: uint64(123), // Fields is any
				},
			},
		}
		encoded := in.Encode().Bytes()
		var out InvokeRequestMessage
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("InvokeResponseMessage", func(t *testing.T) {
		in := InvokeResponseMessage{
			SuppressResponse: true,
			InvokeResponses: []InvokeResponseIB{
				{
					Command: &CommandDataIB{
						Path:   CommandPathIB{CommandId: ptrUint32(3)},
						Fields: uint64(456),
					},
				},
				{
					Status: &CommandStatusIB{
						Path:   CommandPathIB{CommandId: ptrUint32(4)},
						Status: StatusIB{Status: ptrUint8(0)},
					},
				},
			},
		}
		encoded := in.Encode().Bytes()
		var out InvokeResponseMessage
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("TimedRequestMessage", func(t *testing.T) {
		in := TimedRequestMessage{Timeout: 5000}
		encoded := in.Encode().Bytes()
		var out TimedRequestMessage
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})
}
