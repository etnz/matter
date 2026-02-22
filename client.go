package matter

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// Client is a Matter client to exchange with a single peer node.
//
// The Operational discovery is out of scope of for this client it assumes that the PeerAddress is already known and set.
type Client struct {
	network

	// the Fabric used to communicate with the peer.
	Fabric *Fabric
	// PeerAddress used to echange with the Peer Node.
	PeerAddress net.Addr

	// Transport specifies the mechanism by which individual requests are exchanged.
	// If nil, a new ephemeral net.PacketConn is created.
	Transport net.PacketConn

	// chan based network connection for the client to send and receive messages to/from the network layer.
	conn *connection

	initOnce sync.Once
	session  *sessionContext

	exchanges sync.Map
}

var clientNetworkLevel = slog.LevelDebug

func (c *Client) init() {
	c.initOnce.Do(func() {
		c.network.logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: clientNetworkLevel,
		})).With("agent", "client")

		if c.Transport == nil {
			var err error
			c.Transport, err = net.ListenPacket("udp", ":")
			if err != nil {
				panic(fmt.Sprintf("failed to create default transport: %v", err))
			}
		}
		// open up the  chan based network connection.
		c.conn = c.network.new(c.Transport)
		go c.inboundFlow()
	})
}

func (c *Client) Request(msg Message) (resp Message, err error) {
	c.init()

	// Check if we need to bootstrap (Logic: if no session)
	if c.session == nil {
		if err := c.executeCASEFlow(); err != nil {
			return Message{}, err
		}
	}

	respChan := make(chan packet, 1)
	defer close(respChan)
	// 1. Originating Transformations (Client/Initiator Genesis)
	req, err := c.outboundFlow(msg)
	if err != nil {
		return Message{}, err
	}

	// Register the response channel
	c.exchanges.Store(req.protocolHeader.ExchangeID, respChan)
	defer func() {
		c.exchanges.Delete(req.protocolHeader.ExchangeID)
	}()

	var rp packet
	select {
	case rp = <-respChan:
	case <-time.After(5 * time.Second):
		return Message{}, fmt.Errorf("request timed out")
	}

	return Message{
		ProtocolID: rp.protocolHeader.ProtocolId,
		OpCode:     rp.protocolHeader.Opcode,
		Payload:    rp.payload,
	}, nil
}

func (c *Client) executeCASEFlow() error {
	if c.session != nil {
		return nil
	}
	// 1. Bootstrapping Client Outbound (Initiating CASE)
	// Transformation (NewSigma1)
	// The client's Secure Channel Protocol handler generates a Sigma1 message.
	caseCtx := &CASEContext{Fabric: c.Fabric}
	sigma1 := caseCtx.GenerateSigma1()
	sigma1.addr = c.PeerAddress

	// Transition (AssignMessageCounter)
	// Because this is an Unsecured Session, the stack uses and increments the Global Unencrypted Message Counter.
	unsecuredSession := &sessionContext{ID: 0}
	if err := sigma1.AssignMessageCounter(unsecuredSession); err != nil {
		return err
	}

	// Register the response channel for Sigma2
	resp := make(chan packet, 1)
	c.exchanges.Store(sigma1.protocolHeader.ExchangeID, resp)
	defer func() {
		c.exchanges.Delete(sigma1.protocolHeader.ExchangeID)
	}()

	// Transition (Bypass Encryption)
	// The message bypasses standard AEAD encryption and privacy obfuscation since it is sent unencrypted over the network.

	if _, err := sigma1.WriteTo(c.Transport); err != nil {
		return err
	}

	// 4. Bootstrapping Client Inbound (Receiving Sigma2 & Finishing)
	var rp packet
	select {
	case rp = <-resp:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for Sigma2")
	}

	// Check if it is an unencrypted message (Session ID 0)
	if rp.header.SessionID == 0 {
		if rp.protocolHeader.Opcode == OpCodeCASESigma2 {
			sigma3, peerSessionID, err := caseCtx.ParseSigma2(rp.payload)
			if err != nil {
				return err
			}
			// Transformation (NewSigma3)
			// If the server is authenticated, the client generates a Sigma3 message.
			sigma3.addr = c.PeerAddress

			// Handshake complete: Initialize the secure session immediately so we can decrypt SigmaFinished
			encKey, decKey := caseCtx.SessionKeys()
			c.session = &sessionContext{
				ID:            peerSessionID,
				EncryptionKey: encKey,
				DecryptionKey: decKey,
			}

			// Key Derivation and sending Sigma3
			// It transmits Sigma3 to the server.
			if _, err := sigma3.WriteTo(c.Transport); err != nil {
				return err
			}

			// Wait for SigmaFinished (Status Report)
			var rpFinished packet
			select {
			case rpFinished = <-resp:
			case <-time.After(5 * time.Second):
				return fmt.Errorf("timeout waiting for SigmaFinished")
			}
			if rpFinished.protocolHeader.Opcode != OpCodeStatusReport {
				return fmt.Errorf("unexpected message: %v", rpFinished.protocolHeader.Opcode)
			}

			return nil
		}
	}
	return fmt.Errorf("unexpected message during bootstrapping")
}

// ConnectWithPasscode initiates the PASE commissioning flow with the given passcode.
func (c *Client) ConnectWithPasscode(passcode uint32) error {
	c.init()
	if c.session != nil {
		return nil
	}

	paseCtx := &PASEContext{Passcode: passcode}

	// 1. PBKDFParamRequest
	req := paseCtx.GeneratePBKDFParamRequest()
	req.addr = c.PeerAddress

	// Assign message counter for unsecured session
	unsecuredSession := &sessionContext{ID: 0}
	if err := req.AssignMessageCounter(unsecuredSession); err != nil {
		return err
	}

	// Register response channel
	respChan := make(chan packet, 1)
	c.exchanges.Store(req.protocolHeader.ExchangeID, respChan)
	defer func() {
		c.exchanges.Delete(req.protocolHeader.ExchangeID)
	}()

	if _, err := req.WriteTo(c.Transport); err != nil {
		return err
	}

	// 2. Wait for PBKDFParamResponse
	var resp packet
	select {
	case resp = <-respChan:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for PBKDFParamResponse")
	}

	if resp.protocolHeader.Opcode != OpCodePBKDFParamResponse {
		return fmt.Errorf("unexpected opcode: %v", resp.protocolHeader.Opcode)
	}

	// 3. Generate Pake1
	pake1, err := paseCtx.ParsePBKDFParamResponseAndGeneratePake1(resp.payload)
	if err != nil {
		return err
	}
	pake1.addr = c.PeerAddress
	if err := pake1.AssignMessageCounter(unsecuredSession); err != nil {
		return err
	}

	if _, err := pake1.WriteTo(c.Transport); err != nil {
		return err
	}

	// 4. Wait for Pake2
	select {
	case resp = <-respChan:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for Pake2")
	}

	if resp.protocolHeader.Opcode != OpCodePASEPake2 {
		return fmt.Errorf("unexpected opcode: %v", resp.protocolHeader.Opcode)
	}

	// 5. Generate Pake3
	pake3, peerSessionID, err := paseCtx.ParsePake2AndGeneratePake3(resp.payload)
	if err != nil {
		return err
	}
	pake3.addr = c.PeerAddress
	if err := pake3.AssignMessageCounter(unsecuredSession); err != nil {
		return err
	}

	if _, err := pake3.WriteTo(c.Transport); err != nil {
		return err
	}

	// 6. Wait for StatusReport
	select {
	case resp = <-respChan:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for StatusReport")
	}

	if resp.protocolHeader.Opcode != OpCodeStatusReport {
		return fmt.Errorf("unexpected opcode: %v", resp.protocolHeader.Opcode)
	}

	// 7. Derive keys and set session
	encKey, decKey, _ := paseCtx.SessionKeys()
	c.session = &sessionContext{
		ID:            peerSessionID,
		EncryptionKey: encKey,
		DecryptionKey: decKey,
	}

	return nil
}

func (c *Client) outboundFlow(msg Message) (*packet, error) {
	// 1. Originating Transformations (Client/Initiator Genesis)
	// Create a brand new message to initiate a transaction.
	// The node in the Initiator role must allocate a new Exchange ID and always set the Initiator (`I`) flag.
	// The message is bound to an established secure session.
	req := NewRequest(c.session, msg.ProtocolID, msg.OpCode, msg.Payload)
	req.session = c.session
	req.addr = c.PeerAddress // Set the destination address for the request

	// Transition (Reliability Setup)
	// If the message is being dispatched over an unreliable transport like UDP, the Reliability (`R`) flag is set.
	req.protocolHeader.ExchangeFlags |= FlagReliable

	// Transition - AssignMessageCounter
	// The stack retrieves the session's active Local Message Counter and increments it by 1.
	if err := req.AssignMessageCounter(c.session); err != nil {
		return nil, err
	}

	// Transition - EncryptAndAuthenticate
	// Using AES-CCM, the AEAD encryption operation is executed.
	// The Encryption Key bound to the Session ID is used to encrypt the Protocol Header and Application Payload.
	if err := req.EncryptAndAuthenticate(c.session.EncryptionKey); err != nil {
		return nil, err
	}

	// Send the packet to the network
	if _, err := req.WriteTo(c.Transport); err != nil {
		return nil, err
	}
	return req, nil
}

// 4. Client Inbound (Receiving a Response)
// This flow describes the client receiving the server's response datagram and matching it to the original request transaction.
func (c *Client) inboundFlow() {
	for rp := range c.conn.inbound {
		// Transition - DecodeMessageHeader
		if err := rp.DecodeMessageHeader(rp.payload); err != nil {
			c.logger.Warn("failed to decode message header", "error", err)
			continue
		}

		var protocolHeaderDecoded bool
		if rp.header.SessionID != 0 {
			// Transition - DecryptAndAuthenticate
			// The Encryption Key bound to the Session ID is used to encrypt the Protocol Header and Application Payload.
			if c.session != nil {
				if err := rp.DecryptAndAuthenticate(c.session.DecryptionKey); err != nil {
					c.logger.Warn("failed to decrypt and authenticate", "error", err)
					continue
				}
				protocolHeaderDecoded = true
			}
		}

		// Transition - DecodeProtocolHeader / Exchange Matching
		if !protocolHeaderDecoded {
			if err := rp.DecodeProtocolHeader(); err != nil {
				c.logger.Warn("failed to decode protocol header", "error", err)
				continue
			}
		}

		if val, ok := c.exchanges.Load(rp.protocolHeader.ExchangeID); ok {
			if resp, ok := val.(chan packet); ok {
				resp <- rp
			}
		} else {
			c.logger.Warn("dropping message with unknown exchange ID", "exchangeID", rp.protocolHeader.ExchangeID)
		}
	}
}

func (c *Client) Read(req ReadRequestMessage) (ReportDataMessage, error) {
	msg := Message{
		ProtocolID: ProtocolIDInteractionModel,
		OpCode:     OpCodeReadRequest,
		Payload:    req.Encode(),
	}

	resp, err := c.Request(msg)
	if err != nil {
		return ReportDataMessage{}, err
	}

	c.logger.Debug("Received response", "msg", resp)

	if resp.OpCode != OpCodeReportData {
		return ReportDataMessage{}, fmt.Errorf("unexpected opcode: %v", resp.OpCode)
	}

	var out ReportDataMessage
	if err := out.Decode(resp.Payload); err != nil {
		return ReportDataMessage{}, err
	}
	return out, nil
}

func (c *Client) Write(req WriteRequestMessage) (WriteResponseMessage, error) {
	msg := Message{
		ProtocolID: ProtocolIDInteractionModel,
		OpCode:     OpCodeWriteRequest,
		Payload:    req.Encode(),
	}

	resp, err := c.Request(msg)
	if err != nil {
		return WriteResponseMessage{}, err
	}

	if resp.OpCode != OpCodeWriteResponse {
		return WriteResponseMessage{}, fmt.Errorf("unexpected opcode: %v", resp.OpCode)
	}

	var out WriteResponseMessage
	if err := out.Decode(resp.Payload); err != nil {
		return WriteResponseMessage{}, err
	}
	return out, nil
}

func (c *Client) Invoke(req InvokeRequestMessage) (InvokeResponseMessage, error) {
	msg := Message{
		ProtocolID: ProtocolIDInteractionModel,
		OpCode:     OpCodeInvokeRequest,
		Payload:    req.Encode(),
	}

	resp, err := c.Request(msg)
	if err != nil {
		return InvokeResponseMessage{}, err
	}

	if resp.OpCode != OpCodeInvokeResponse {
		return InvokeResponseMessage{}, fmt.Errorf("unexpected opcode: %v", resp.OpCode)
	}

	var out InvokeResponseMessage
	if err := out.Decode(resp.Payload); err != nil {
		return InvokeResponseMessage{}, err
	}
	return out, nil
}

func (c *Client) Subscribe(req SubscribeRequestMessage) (SubscribeResponseMessage, error) {
	msg := Message{
		ProtocolID: ProtocolIDInteractionModel,
		OpCode:     OpCodeSubscribeRequest,
		Payload:    req.Encode(),
	}

	resp, err := c.Request(msg)
	if err != nil {
		return SubscribeResponseMessage{}, err
	}

	if resp.OpCode != OpCodeSubscribeResponse {
		return SubscribeResponseMessage{}, fmt.Errorf("unexpected opcode: %v", resp.OpCode)
	}

	var out SubscribeResponseMessage
	if err := out.Decode(resp.Payload); err != nil {
		return SubscribeResponseMessage{}, err
	}
	return out, nil
}

func (c *Client) TimedRequest(req TimedRequestMessage) (StatusResponseMessage, error) {
	msg := Message{
		ProtocolID: ProtocolIDInteractionModel,
		OpCode:     OpCodeTimedRequest,
		Payload:    req.Encode(),
	}

	resp, err := c.Request(msg)
	if err != nil {
		return StatusResponseMessage{}, err
	}

	if resp.OpCode != OpCodeStatusResponse {
		return StatusResponseMessage{}, fmt.Errorf("unexpected opcode: %v", resp.OpCode)
	}

	var out StatusResponseMessage
	if err := out.Decode(resp.Payload); err != nil {
		return StatusResponseMessage{}, err
	}
	return out, nil
}

// TODO: We need a special method to initiate the commisioning. It must take the passcode, put it in the PASEContext and kick the bootstrapping flow.

// TODO: we don't have the MRP flow implemented yet (regression).
