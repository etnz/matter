package matter

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/etnz/matter/securechannel"
)

// Client is a Matter client to exchange with a single peer node.
//
// The Operational discovery is out of scope of for this client it assumes that the PeerAddress is already known and set.
type Client struct {
	network

	// peerAddress used to echange with the Peer Node.
	peerAddress net.Addr

	// the fabric used to communicate with the peer.
	fabric *securechannel.Fabric

	// transport specifies the mechanism by which individual requests are exchanged.
	// If nil, a new ephemeral net.PacketConn is created.
	transport net.PacketConn

	// chan based network connection for the client to send and receive messages to/from the network layer.
	conn *connection

	initOnce sync.Once
	session  *securechannel.SessionContext

	exchanges sync.Map
	mrp       *mrpEngine
}

var clientNetworkLevel = slog.LevelDebug

// NewCommissionedClient creates a new Client for a commissioned node.
func NewCommissionedClient(transport net.PacketConn, peerAddress net.Addr, fabric *securechannel.Fabric) (*Client, error) {
	c := &Client{
		transport:   transport,
		peerAddress: peerAddress,
		fabric:      fabric,
	}
	if err := c.ConnectWithFabric(fabric); err != nil {
		return nil, err
	}
	return c, nil
}

// NewPasscodeClient creates a new Client using a passcode (PASE).
func NewPasscodeClient(transport net.PacketConn, peerAddress net.Addr, passcode uint32) (*Client, error) {
	c := &Client{
		transport:   transport,
		peerAddress: peerAddress,
	}
	if err := c.ConnectWithPasscode(passcode); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) init() {
	c.initOnce.Do(func() {
		c.network.logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: clientNetworkLevel,
		})).With("agent", "client")

		if c.transport == nil {
			var err error
			c.transport, err = net.ListenPacket("udp", ":")
			if err != nil {
				panic(fmt.Sprintf("failed to create default transport: %v", err))
			}
		}
		// open up the  chan based network connection.
		c.conn = c.network.new(c.transport)
		c.mrp = newMRPEngine(c.conn.outbound, c.network.logger)
		go c.inboundFlow()
	})
}

// Request executes a request-response transaction with the peer node.
// A secure connection must have been established (e.g. via ConnectWithPasscode or ConnectWithCertificate) before calling this method.
func (c *Client) Request(msg Message) (resp Message, err error) {
	c.init()

	// Check if we need to bootstrap (Logic: if no session)
	if c.session == nil {
		return Message{}, fmt.Errorf("no session established")
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

func (c *Client) ConnectWithFabric(f *securechannel.Fabric) error {
	c.fabric = f
	c.init()
	if c.session != nil {
		c.session = nil // Clear any existing session
	}
	// Bootstrapping Client Outbound (Initiating CASE)
	c.logger.Debug("CASE sending Sigma1")

	// Create a new session context for CASE, that will be completed in the flow. The session keys will be populated after handling Sigma2.
	newSession, sigma1Payload, err := securechannel.NewClientSession(f)
	if err != nil {
		return err
	}

	sigma1 := NewRequest(newSession, ProtocolIDSecureChannel, OpCodeCASESigma1, sigma1Payload)
	sigma1.addr = c.peerAddress

	//  AssignMessageCounter
	// Because this is an Unsecured Session, the stack uses and increments the Global Unencrypted Message Counter.
	unsecuredSession := &securechannel.SessionContext{ID: 0}
	if err := sigma1.AssignMessageCounter(unsecuredSession); err != nil {
		return err
	}

	// Register the response channel for Sigma2
	resp := make(chan packet, 2) // Need space for Sigma2 and StatusReport
	c.exchanges.Store(sigma1.protocolHeader.ExchangeID, resp)
	defer func() {
		c.exchanges.Delete(sigma1.protocolHeader.ExchangeID)
	}()

	c.conn.outbound <- *sigma1

	// Wait for Sigma2.
	var rp packet
	select {
	case rp = <-resp: // Sigma2
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for Sigma2")
	}

	// Check if it is an unencrypted message (Session ID 0)
	if rp.header.SessionID == 0 {
		if rp.protocolHeader.Opcode == OpCodeCASESigma2 {
			sigma3Payload, err := newSession.HandleSigma2(rp.payload)
			if err != nil {
				c.logger.Error("failed to handle Sigma2", "err", err)
				report := rp.NewStatusReport(uint16(securechannel.GeneralCodeFailure), ProtocolIDSecureChannel, uint16(securechannel.CodeInvalidParameter), nil)
				unsecuredSession := &securechannel.SessionContext{ID: 0}
				report.AssignMessageCounter(unsecuredSession)
				report.protocolHeader.ExchangeFlags |= FlagReliable
				c.mrp.registerReliableMessage(report)
				c.conn.outbound <- report
				return err
			}
			// Transformation (NewSigma3)
			c.logger.Debug("CASE send Sigma3")
			sigma3 := rp.NewResponse(Message{
				ProtocolID: ProtocolIDSecureChannel,
				OpCode:     OpCodeCASESigma3,
				Payload:    sigma3Payload,
			})

			c.session = newSession

			sigma3.header.SessionID = newSession.ID
			if err := sigma3.AssignMessageCounter(newSession); err != nil {
				return err
			}

			c.conn.outbound <- sigma3

			// Wait for SigmaFinished (Status Report)
			var rpFinished packet
			select {
			case rpFinished = <-resp:
			case <-time.After(5 * time.Second):
				c.session = nil // Clear session on failure
				return fmt.Errorf("timeout waiting for SigmaFinished")
			}
			if rpFinished.protocolHeader.Opcode != OpCodeStatusReport {
				c.session = nil // Clear session on failure
				return fmt.Errorf("unexpected message: %v", rpFinished.protocolHeader.Opcode)
			}

			var sr securechannel.StatusReport
			if err := sr.Decode(rpFinished.payload); err != nil {
				c.session = nil
				return fmt.Errorf("failed to decode status report: %v", err)
			}
			if sr.GeneralCode != securechannel.GeneralCodeSuccess {
				c.session = nil
				return fmt.Errorf("session establishment has failed: %v", sr.GeneralCode)
			}

			return nil
		} else {
			return fmt.Errorf("unexpected message during bootstrapping: %v", rp.protocolHeader.Opcode.String(rp.protocolHeader.ProtocolId))
		}
	}
	return fmt.Errorf("unexpected session message during bootstrapping: %v", rp)
}

// ConnectWithPasscode initiates the PASE commissioning flow with the given passcode.
func (c *Client) ConnectWithPasscode(passcode uint32) error {
	c.init()
	if c.session != nil {
		return nil
	}
	// creates a PASE context.
	paseCtx := &securechannel.PASEContext{Passcode: passcode}

	// 1. PBKDFParamRequest
	payload, err := paseCtx.GeneratePBKDFParamRequest()
	if err != nil {
		return err
	}
	req := NewRequest(nil, ProtocolIDSecureChannel, OpCodePBKDFParamRequest, payload)
	req.addr = c.peerAddress

	// Assign message counter for unsecured session
	unsecuredSession := &securechannel.SessionContext{ID: 0}
	if err := req.AssignMessageCounter(unsecuredSession); err != nil {
		return err
	}
	paseCtx.ExchangeID = req.protocolHeader.ExchangeID

	// Register response channel
	respChan := make(chan packet, 1)
	c.exchanges.Store(req.protocolHeader.ExchangeID, respChan)
	defer func() {
		c.exchanges.Delete(req.protocolHeader.ExchangeID)
	}()

	// send the PBKDFParamRequest
	c.conn.outbound <- *req

	// Wait for PBKDFParamResponse
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
	pake1Payload, err := paseCtx.ParsePBKDFParamResponseAndGeneratePake1(resp.payload)
	if err != nil {
		return err
	}
	pake1 := resp.NewResponse(Message{
		ProtocolID: ProtocolIDSecureChannel,
		OpCode:     OpCodePASEPake1,
		Payload:    pake1Payload,
	})
	if err := pake1.AssignMessageCounter(unsecuredSession); err != nil {
		return err
	}

	c.conn.outbound <- pake1

	// Wait for Pake2
	select {
	case resp = <-respChan:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for Pake2")
	}

	if resp.protocolHeader.Opcode != OpCodePASEPake2 {
		return fmt.Errorf("unexpected opcode: %v", resp.protocolHeader.Opcode)
	}

	// Generate Pake3
	pake3Payload, peerSessionID, err := paseCtx.ParsePake2AndGeneratePake3(resp.payload)
	if err != nil {
		c.logger.Error("failed to handle Pake2", "err", err)
		report := resp.NewStatusReport(uint16(securechannel.GeneralCodeFailure), ProtocolIDSecureChannel, uint16(securechannel.CodeInvalidParameter), nil)
		unsecuredSession := &securechannel.SessionContext{ID: 0}
		report.AssignMessageCounter(unsecuredSession)
		report.protocolHeader.ExchangeFlags |= FlagReliable
		c.mrp.registerReliableMessage(report)
		c.conn.outbound <- report
		return err
	}
	pake3 := resp.NewResponse(Message{
		ProtocolID: ProtocolIDSecureChannel,
		OpCode:     OpCodePASEPake3,
		Payload:    pake3Payload,
	})
	if err := pake3.AssignMessageCounter(unsecuredSession); err != nil {
		return err
	}

	// 7. Derive keys and set session
	// We need to establish the session before receiving the StatusReport,
	// because the StatusReport is encrypted with the new session keys.
	encKey, decKey, _ := paseCtx.SessionKeys()
	c.session = &securechannel.SessionContext{
		ID:            peerSessionID,
		EncryptionKey: encKey,
		DecryptionKey: decKey,
	}

	c.conn.outbound <- pake3

	// Wait for StatusReport
	select {
	case resp = <-respChan:
	case <-time.After(5 * time.Second):
		c.session = nil // Clear session on failure
		return fmt.Errorf("timeout waiting for StatusReport")
	}

	if resp.protocolHeader.Opcode != OpCodeStatusReport {
		c.session = nil // Clear session on failure
		return fmt.Errorf("unexpected opcode: %v", resp.protocolHeader.Opcode)
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
	req.addr = c.peerAddress // Set the destination address for the request

	// Transition (Reliability Setup)
	// If the message is being dispatched over an unreliable transport like UDP, the Reliability (`R`) flag is set.
	req.protocolHeader.ExchangeFlags |= FlagReliable

	// Piggyback ACK
	if ackCounter, ok := c.mrp.piggybackAck(req.protocolHeader.ExchangeID); ok {
		req.PiggybackAck(ackCounter)
	}

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

	// Register for retransmission
	c.mrp.registerReliableMessage(*req)

	// Send the packet to the network
	c.conn.outbound <- *req
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

		if rp.header.SessionID != 0 {
			if c.session != nil && c.session.ID == rp.header.SessionID {
				rp.session = c.session
			} else {
				c.logger.Debug("dropping message with unknown session ID", "sessionID", rp.header.SessionID)
				continue
			}
		}

		// Handle Duplicates
		if err := rp.ProcessMessageCounter(); err != nil {
			if err == ErrDuplicateMessage && (rp.protocolHeader.ExchangeFlags&FlagReliable) != 0 {
				// Send Standalone ACK immediately
				c.mrp.sendStandaloneAck(&rp)
			}
			c.logger.Warn("dropping duplicate or invalid message", "error", err)
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

		// MRP Hooks
		if (rp.protocolHeader.ExchangeFlags & FlagAck) != 0 {
			c.mrp.acknowledgeMessage(rp.protocolHeader.AckCounter)
		}
		if (rp.protocolHeader.ExchangeFlags & FlagReliable) != 0 {
			c.mrp.scheduleAck(&rp)
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
		Payload:    req.Encode().Bytes(),
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
		Payload:    req.Encode().Bytes(),
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
		Payload:    req.Encode().Bytes(),
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
		Payload:    req.Encode().Bytes(),
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
		Payload:    req.Encode().Bytes(),
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

// Close terminates the session with the peer node.
func (c *Client) Close() error {
	if c.session != nil {
		sr := securechannel.StatusReport{
			GeneralCode:  securechannel.GeneralCodeSuccess,
			ProtocolID:   uint32(ProtocolIDSecureChannel),
			ProtocolCode: securechannel.CodeCloseSession,
		}
		msg := Message{
			ProtocolID: ProtocolIDSecureChannel,
			OpCode:     OpCodeStatusReport,
			Payload:    sr.Encode(),
		}
		_, err := c.outboundFlow(msg)
		c.session = nil
		return err
	}
	return nil
}
