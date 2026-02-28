package matter

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/etnz/matter/securechannel"
)

func TestMRPEngine_Retransmission(t *testing.T) {
	outbound := make(chan packet, 10)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mrp := newMRPEngine(outbound, logger)
	defer mrp.stop()

	// 1. Register a reliable message
	// The initial send is handled by the caller, MRP handles retransmissions.
	req := packet{
		header: messageHeader{
			MessageCounter: 1001,
			SessionID:      1,
		},
		protocolHeader: protocolMessageHeader{
			ExchangeID:    50,
			ExchangeFlags: FlagInitiator | FlagReliable,
		},
		payload: []byte("test payload"),
	}

	mrp.registerReliableMessage(req)

	// 2. Wait for first retransmission
	// Base interval is 300ms.
	select {
	case p := <-outbound:
		if p.header.MessageCounter != 1001 {
			t.Errorf("expected retransmission of msg 1001, got %d", p.header.MessageCounter)
		}
		if p.protocolHeader.ExchangeID != 50 {
			t.Errorf("expected exchange ID 50, got %d", p.protocolHeader.ExchangeID)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for first retransmission")
	}

	// 3. Acknowledge the message
	mrp.acknowledgeMessage(1001)

	// 4. Ensure no more retransmissions
	select {
	case p := <-outbound:
		t.Fatalf("unexpected retransmission after ACK: %v", p)
	case <-time.After(400 * time.Millisecond):
		// Success
	}
}

func TestMRPEngine_StandaloneAck(t *testing.T) {
	outbound := make(chan packet, 10)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mrp := newMRPEngine(outbound, logger)
	defer mrp.stop()

	// 1. Schedule an ACK for an incoming message
	// Use SessionID 0 to avoid encryption logic in test (which requires keys)
	req := &packet{
		header: messageHeader{
			MessageCounter:    2002,
			SessionID:         0,
			SourceNodeID:      []byte{1, 2, 3, 4, 5, 6, 7, 8},
			DestinationNodeID: []byte{8, 7, 6, 5, 4, 3, 2, 1},
		},
		protocolHeader: protocolMessageHeader{
			ExchangeID: 60,
		},
		session: &securechannel.SessionContext{ID: 0},
	}

	mrp.scheduleAck(req)

	// 2. Wait for Standalone ACK
	// Timeout is 200ms.
	select {
	case p := <-outbound:
		if (p.protocolHeader.ExchangeFlags & FlagAck) == 0 {
			t.Error("expected Ack flag set")
		}
		if p.protocolHeader.Opcode != OpCodeMRPStandaloneAck {
			t.Errorf("expected OpCodeMRPStandaloneAck, got %v", p.protocolHeader.Opcode)
		}
		if p.protocolHeader.AckCounter != 2002 {
			t.Errorf("expected AckCounter 2002, got %d", p.protocolHeader.AckCounter)
		}
		if p.protocolHeader.ExchangeID != 60 {
			t.Errorf("expected ExchangeID 60, got %d", p.protocolHeader.ExchangeID)
		}
		// Verify NodeID swap
		if string(p.header.SourceNodeID) != string(req.header.DestinationNodeID) {
			t.Error("expected SourceNodeID to be swapped")
		}
		if string(p.header.DestinationNodeID) != string(req.header.SourceNodeID) {
			t.Error("expected DestinationNodeID to be swapped")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("timeout waiting for standalone ACK")
	}
}

func TestMRPEngine_PiggybackAck(t *testing.T) {
	outbound := make(chan packet, 10)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mrp := newMRPEngine(outbound, logger)
	defer mrp.stop()

	// 1. Schedule an ACK
	req := &packet{
		header: messageHeader{
			MessageCounter: 3003,
		},
		protocolHeader: protocolMessageHeader{
			ExchangeID: 70,
		},
	}
	mrp.scheduleAck(req)

	// 2. Piggyback before timeout
	ackCounter, ok := mrp.piggybackAck(70)
	if !ok {
		t.Fatal("expected piggybackAck to return true")
	}
	if ackCounter != 3003 {
		t.Errorf("expected ackCounter 3003, got %d", ackCounter)
	}

	// 3. Ensure no Standalone ACK is sent later
	select {
	case p := <-outbound:
		t.Fatalf("unexpected standalone ACK after piggyback: %v", p)
	case <-time.After(300 * time.Millisecond):
		// Success
	}
}

func TestMRPEngine_MaxRetransmissions(t *testing.T) {
	outbound := make(chan packet, 10)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mrp := newMRPEngine(outbound, logger)
	defer mrp.stop()

	req := packet{
		header:         messageHeader{MessageCounter: 4004},
		protocolHeader: protocolMessageHeader{ExchangeID: 80},
	}
	mrp.registerReliableMessage(req)

	// Max transmissions is 5.
	// Intervals grow: 300ms, ~480ms, ~768ms, ~1228ms, ~1966ms.
	// We expect 5 retransmissions.

	for i := 1; i <= 5; i++ {
		select {
		case <-outbound:
			// received retransmission i
		case <-time.After(3 * time.Second): // Generous timeout for backoff
			t.Fatalf("timeout waiting for retransmission %d", i)
		}
	}

	// Ensure no more
	select {
	case p := <-outbound:
		t.Fatalf("unexpected retransmission #6: %v", p)
	case <-time.After(3 * time.Second):
		// Success
	}
}
