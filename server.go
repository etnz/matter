package matter

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/etnz/matter/securechannel"
)

// temporary hack to tune the verbosity level of the the server.
var serverNetworkLevel = slog.LevelDebug

// MessageWriter allows the handler to write a response.
type MessageWriter interface {
	Response(Message)
}

// Handler responds to an incoming Matter request.
type Handler interface {
	Serve(ctx context.Context, msg Message, w MessageWriter)
}

// HandlerFunc is an adapter to allow the use of ordinary functions as Matter handlers.
type HandlerFunc func(ctx context.Context, msg Message, w MessageWriter)

// Serve calls f(ctx).
func (f HandlerFunc) Serve(ctx context.Context, msg Message, w MessageWriter) {
	f(ctx, msg, w)
}

// responseWriter implements MessageWriter and sends the response back to the connection loop.
type responseWriter struct {
	response **Message
}

func (w responseWriter) Response(msg Message) { *w.response = &msg }

// Server defines parameters for running a Matter server.
type Server struct {
	network

	// Addr optionally specifies the UDP address for the server to listen on,
	// in the form "host:port". If empty, ":5540" (standard Matter port) is used.
	Addr     string
	Passcode uint32

	// Handler to be invoked for incoming requests that don't match secure channel protocol or Interaction Model handlers below.
	Handler Handler

	// Interaction Model Handlers
	ReadHandler         func(context.Context, ReadRequestMessage) (ReportDataMessage, error)
	WriteHandler        func(context.Context, WriteRequestMessage) (WriteResponseMessage, error)
	InvokeHandler       func(context.Context, InvokeRequestMessage) (InvokeResponseMessage, error)
	SubscribeHandler    func(context.Context, SubscribeRequestMessage) (SubscribeResponseMessage, error)
	TimedRequestHandler func(context.Context, TimedRequestMessage) (StatusResponseMessage, error)
	ReportDataHandler   func(context.Context, ReportDataMessage) (StatusResponseMessage, error)

	// BaseContext optionally specifies a function that returns the base context
	// for incoming requests on this server.
	BaseContext func(net.Addr) context.Context

	Fabric *securechannel.Fabric

	initOnce sync.Once
	// map session ID to session context. Session is established after CASE or PASE handshake completes, and used for subsequent messages.
	sessions sync.Map
	// map exchange ID to PASE context. PASE context is created during the PASE handshake and deleted after the handshake completes.
	// pase are stored per exchange ID and not session ID because the session is not established until the handshake completes,
	// but we need to keep track of the PASE context during the handshake which may involve multiple messages (PBKDFParamRequest/Response, PASEPake1/2/3).
	paseSessions sync.Map
	mrp          *mrpEngine
}

// ListenAndServe listens on the UDP network address s.Addr and then calls Serve.
func (s *Server) ListenAndServe() error {
	s.init()
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

func (s *Server) init() {
	s.initOnce.Do(func() {
		s.network.logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: serverNetworkLevel,
		})).With("agent", "server")
	})
}

// Serve accepts incoming packets on the PacketConn and creates a new service goroutine for each.
func (s *Server) Serve(pc net.PacketConn) (err error) {
	// Ensure that everything is ready.
	s.init()

	conn := s.network.new(pc)
	defer conn.close()
	s.mrp = newMRPEngine(conn.outbound, s.network.logger)
	defer s.mrp.stop()

	for msg := range conn.inbound {
		// Build a Response to this Request, using the Handler.
		go s.handle(msg, conn.outbound)

	}
	return nil
}

func (s *Server) handle(msg packet, outbound chan<- packet) {
	// create a context and a go routine per request to build Response.
	var ctx context.Context
	if s.BaseContext != nil {
		ctx = s.BaseContext(msg.addr)
	} else {
		ctx = context.Background()
	}

	// execute the inbound flow to parse the message and build a MatterMessage.
	if err := s.inboundFlow(ctx, &msg); err != nil {
		s.network.logger.Warn("failed to process inbound message", "error", err)
		return
	}

	// Delegate to the Handler to build an Application Response.
	var response *Message

	isSecureChannel := msg.protocolHeader.ProtocolId == ProtocolIDSecureChannel
	isInteractionModel := msg.protocolHeader.ProtocolId == ProtocolIDInteractionModel
	opCode := msg.protocolHeader.Opcode

	switch {
	case isSecureChannel && opCode == OpCodeCASESigma1:
		// Sigma1 initiate the flow to establish a new session.
		// First establishes the temporary CASE context for this exchange.
		s.logger.Debug("handling Sigma1")
		session, payload, err := securechannel.NewServerSessionFromSigma1(s.Fabric, msg.payload)
		if err != nil {
			s.network.logger.Warn("failed to handle Sigma1", "error", err)
			response = s.newStatusReport(securechannel.GeneralCodeFailure, securechannel.CodeInvalidParameter)
		} else {
			// create a new incomplete session to handle future exchanges.
			s.sessions.Store(session.ID, session)

			response = &Message{
				ProtocolID: ProtocolIDSecureChannel,
				OpCode:     OpCodeCASESigma2,
				Payload:    payload,
			}
		}

	case isSecureChannel && opCode == OpCodeCASESigma3:
		if msg.session == nil {
			s.network.logger.Warn("failed to handle Sigma3", "error", fmt.Errorf("sigma3 received without session context"))
			response = s.newStatusReport(securechannel.GeneralCodeFailure, securechannel.CodeInvalidParameter)
		} else {
			s.logger.Debug("handling Sigma3", "sessionID", msg.session.ID)

			payload, err := msg.session.HandleSigma3(msg.payload)
			if err != nil {
				s.network.logger.Warn("failed to handle Sigma3", "error", err)
				response = s.newStatusReport(securechannel.GeneralCodeFailure, securechannel.CodeInvalidParameter)
				s.sessions.Delete(msg.session.ID)
				msg.session.ID = 0
			} else {
				response = &Message{ProtocolID: ProtocolIDSecureChannel, OpCode: OpCodeStatusReport, Payload: payload}
			}
		}

	case isSecureChannel && opCode == OpCodePBKDFParamRequest:
		//
		passcode := s.Passcode
		if passcode == 0 {
			passcode = 20202021 // Default passcode
		}
		paseCtx, payload, err := securechannel.NewPASEContextFromPBKDFParamRequest(passcode, msg.payload)
		if err != nil {
			s.network.logger.Warn("failed to handle PBKDFParamRequest", "error", err)
			response = s.newStatusReport(securechannel.GeneralCodeFailure, securechannel.CodeInvalidParameter)
		} else {
			//
			s.paseSessions.Store(msg.protocolHeader.ExchangeID, paseCtx)

			response = &Message{
				ProtocolID: ProtocolIDSecureChannel,
				OpCode:     OpCodePBKDFParamResponse,
				Payload:    payload,
			}
		}

	case isSecureChannel && opCode == OpCodePASEPake1:
		val, ok := s.paseSessions.Load(msg.protocolHeader.ExchangeID)
		if !ok {
			s.network.logger.Warn("failed to handle Pake1", "error", fmt.Errorf("PASE context not found"))
			response = s.newStatusReport(securechannel.GeneralCodeFailure, securechannel.CodeInvalidParameter)
		} else {
			paseCtx := val.(*securechannel.PASEContext)

			payload, err := paseCtx.ParsePake1AndGeneratePake2(msg.payload)
			if err != nil {
				s.network.logger.Warn("failed to handle Pake1", "error", err)
				response = s.newStatusReport(securechannel.GeneralCodeFailure, securechannel.CodeInvalidParameter)
			} else {
				response = &Message{
					ProtocolID: ProtocolIDSecureChannel,
					OpCode:     OpCodePASEPake2,
					Payload:    payload,
				}
			}
		}

	case isSecureChannel && opCode == OpCodePASEPake3:
		val, ok := s.paseSessions.Load(msg.protocolHeader.ExchangeID)
		if !ok {
			s.network.logger.Warn("failed to handle Pake3", "error", fmt.Errorf("PASE context not found"))
			response = s.newStatusReport(securechannel.GeneralCodeFailure, securechannel.CodeInvalidParameter)
		} else {
			paseCtx := val.(*securechannel.PASEContext)

			payload, err := paseCtx.ParsePake3(msg.payload)
			if err != nil {
				s.network.logger.Warn("failed to handle Pake3", "error", err)
				response = s.newStatusReport(securechannel.GeneralCodeFailure, securechannel.CodeInvalidParameter)
			} else {
				// Side effect is to retrieve keys, create a session and delete the pase context.
				enc, dec, _ := paseCtx.SessionKeys()
				session := &securechannel.SessionContext{
					ID:            paseCtx.ResponderSessionID,
					DecryptionKey: enc,
					EncryptionKey: dec,
				}
				s.sessions.Store(session.ID, session)
				s.paseSessions.Delete(msg.protocolHeader.ExchangeID)
				response = &Message{ProtocolID: ProtocolIDSecureChannel, OpCode: OpCodeStatusReport, Payload: payload}
			}
		}

	case isInteractionModel && opCode == OpCodeReadRequest && s.ReadHandler != nil:
		var req ReadRequestMessage
		if err := req.Decode(msg.payload); err != nil {
			s.network.logger.Error("decode failed", "error", err)
			return
		}
		resp, err := s.ReadHandler(ctx, req)
		if err != nil {
			s.network.logger.Error("handler failed", "error", err)
			return
		}
		response = &Message{
			ProtocolID: ProtocolIDInteractionModel,
			OpCode:     OpCodeReportData,
			Payload:    resp.Encode().Bytes(),
		}

	case isInteractionModel && opCode == OpCodeWriteRequest && s.WriteHandler != nil:
		var req WriteRequestMessage
		if err := req.Decode(msg.payload); err != nil {
			s.network.logger.Error("decode failed", "error", err)
			return
		}
		resp, err := s.WriteHandler(ctx, req)
		if err != nil {
			s.network.logger.Error("handler failed", "error", err)
			return
		}
		response = &Message{
			ProtocolID: ProtocolIDInteractionModel,
			OpCode:     OpCodeWriteResponse,
			Payload:    resp.Encode().Bytes(),
		}

	case isInteractionModel && opCode == OpCodeInvokeRequest && s.InvokeHandler != nil:
		var req InvokeRequestMessage
		if err := req.Decode(msg.payload); err != nil {
			s.network.logger.Error("decode failed", "error", err)
			return
		}
		resp, err := s.InvokeHandler(ctx, req)
		if err != nil {
			s.network.logger.Error("handler failed", "error", err)
			return
		}
		response = &Message{
			ProtocolID: ProtocolIDInteractionModel,
			OpCode:     OpCodeInvokeResponse,
			Payload:    resp.Encode().Bytes(),
		}

	case isInteractionModel && opCode == OpCodeSubscribeRequest && s.SubscribeHandler != nil:
		var req SubscribeRequestMessage
		if err := req.Decode(msg.payload); err != nil {
			s.network.logger.Error("decode failed", "error", err)
			return
		}
		resp, err := s.SubscribeHandler(ctx, req)
		if err != nil {
			s.network.logger.Error("handler failed", "error", err)
			return
		}
		response = &Message{
			ProtocolID: ProtocolIDInteractionModel,
			OpCode:     OpCodeSubscribeResponse,
			Payload:    resp.Encode().Bytes(),
		}

	case isInteractionModel && opCode == OpCodeTimedRequest && s.TimedRequestHandler != nil:
		var req TimedRequestMessage
		if err := req.Decode(msg.payload); err != nil {
			s.network.logger.Error("decode failed", "error", err)
			return
		}
		resp, err := s.TimedRequestHandler(ctx, req)
		if err != nil {
			s.network.logger.Error("handler failed", "error", err)
			return
		}
		response = &Message{
			ProtocolID: ProtocolIDInteractionModel,
			OpCode:     OpCodeStatusResponse,
			Payload:    resp.Encode().Bytes(),
		}

	case isInteractionModel && opCode == OpCodeReportData && s.ReportDataHandler != nil:
		var req ReportDataMessage
		if err := req.Decode(msg.payload); err != nil {
			s.network.logger.Error("decode failed", "error", err)
			return
		}
		resp, err := s.ReportDataHandler(ctx, req)
		if err != nil {
			s.network.logger.Error("handler failed", "error", err)
			return
		}
		response = &Message{
			ProtocolID: ProtocolIDInteractionModel,
			OpCode:     OpCodeStatusResponse,
			Payload:    resp.Encode().Bytes(),
		}

	case s.Handler != nil:
		req := Message{
			ProtocolID: msg.protocolHeader.ProtocolId,
			OpCode:     msg.protocolHeader.Opcode,
			Payload:    msg.payload,
		}
		s.Handler.Serve(ctx, req, responseWriter{response: &response})
	}

	if response != nil {
		// response now contains that response, run the outbound flow to serialize and send the response back to the client.
		s.outboundFlow(ctx, msg, *response, outbound)
	}
}

func (s *Server) newStatusReport(generalCode securechannel.GeneralCode, protocolCode securechannel.ProtocolCode) *Message {
	sr := securechannel.StatusReport{
		GeneralCode:  generalCode,
		ProtocolID:   uint32(ProtocolIDSecureChannel),
		ProtocolCode: protocolCode,
	}
	return &Message{
		ProtocolID: ProtocolIDSecureChannel,
		OpCode:     OpCodeStatusReport,
		Payload:    sr.Encode(),
	}
}

func (s *Server) outboundFlow(ctx context.Context, req packet, resp Message, outbound chan<- packet) {
	// 3. Flow 3: Server Outbound (Sending a Response)
	// This flow describes the server application reacting to the received request, generating a response, and preparing it for the network.

	// Transformation - NewResponse
	// The server application handler generates a response message (or Status Report).
	// It utilizes the exact Exchange ID from the incoming request.
	// Because the server is the Responder, the Initiator (`I`) flag is set to 0.
	outPkt := req.NewResponse(resp)

	// SessionLess response.
	if req.header.SessionID == 0 {

		// Transition: The server allocates a Local Session Identifier for the future secure session,
		// assigns an unencrypted message counter, and sends Sigma2 back to the client.
		sessionCtx := &securechannel.SessionContext{ID: 0}
		if err := outPkt.AssignMessageCounter(sessionCtx); err != nil {
			s.network.logger.Error("failed to assign message counter", "error", err)
			return
		}

		// Send the response back to the network layer (Bypass Encryption)
		select {
		case outbound <- outPkt:
		case <-ctx.Done():
		}
		return
	}
	// normal flow with session. Session was established in the inbound flow and passed through the response.

	// PiggybackAck
	// Before the message is finalized, the server checks its Acknowledgement Table.
	// Finding the pending acknowledgement for the client's request, it sets the `A` (Acknowledgement) flag to 1
	// and injects the client's `Acknowledged Message Counter` into the outbound Protocol Header.
	if (req.protocolHeader.ExchangeFlags & FlagReliable) != 0 {
		if ackCounter, ok := s.mrp.piggybackAck(req.protocolHeader.ExchangeID); ok {
			outPkt.PiggybackAck(ackCounter)
		}
	}

	// AssignMessageCounter
	// The server retrieves and increments its own Local Message Counter for the outgoing session.
	if err := outPkt.AssignMessageCounter(outPkt.session); err != nil {
		s.network.logger.Error("failed to assign message counter", "error", err)
		return
	}

	// EncryptAndAuthenticate
	// The payload and protocol header are encrypted using AES-CCM with the session's Encryption Key.
	if outPkt.session.Secured() {
		if err := outPkt.EncryptAndAuthenticate(outPkt.session.EncryptionKey); err != nil {
			s.network.logger.Error("failed to encrypt", "error", err)
			return
		}
	}

	// Register Reliable
	if (outPkt.protocolHeader.ExchangeFlags & FlagReliable) != 0 {
		s.mrp.registerReliableMessage(outPkt)
	}

	// Send the response back to the network layer
	select {
	case outbound <- outPkt:
	case <-ctx.Done():
	}
}

func (s *Server) inboundFlow(ctx context.Context, req *packet) error {
	// Server Inbound (Receiving a Request)
	// This flow describes a server receiving the physical datagram from the network and processing it up the stack.

	// DecodeMessageHeader
	// The unencrypted Message Header is parsed to extract the Session ID, Message Flags, and Security Flags.
	if err := req.DecodeMessageHeader(req.payload); err != nil {
		s.network.logger.Warn("failed to decode message header", "error", err)
		return err
	}

	// SessionLess: bootstrapping a Session via CASE or PASE, return the protocol header unspoiled (no decryption)
	if req.header.SessionID == 0 {
		// The server checks the unencrypted message counter against its Unsecured Session Context.
		if err := req.ProcessMessageCounter(); err != nil {
			if err == ErrDuplicateMessage {
				// Try to decode protocol header to see if we need to ACK
				if errDecode := req.DecodeProtocolHeader(); errDecode == nil {
					if (req.protocolHeader.ExchangeFlags & FlagReliable) != 0 {
						s.mrp.sendStandaloneAck(req)
					}
				}
			}
			s.network.logger.Warn("replay detected or invalid counter", "error", err)
			return err
		}

		// Transformation (CreateExchange & Route)
		// Because the message has the PROTOCOL_ID_SECURE_CHANNEL Protocol ID and Sigma1 Opcode,
		// the Exchange Layer routes it directly to the Secure Channel protocol handlers.
		if err := req.DecodeProtocolHeader(); err != nil {
			s.network.logger.Warn("failed to decode protocol header", "error", err)
			return err
		}

		// MRP Hooks
		if (req.protocolHeader.ExchangeFlags & FlagAck) != 0 {
			s.mrp.acknowledgeMessage(req.protocolHeader.AckCounter)
		}
		if (req.protocolHeader.ExchangeFlags & FlagReliable) != 0 {
			s.mrp.scheduleAck(req)
		}
		return nil
	}

	// Resolve Session
	if val, ok := s.sessions.Load(req.header.SessionID); ok {
		req.session = val.(*securechannel.SessionContext)
	} else {
		return fmt.Errorf("unknown session %d", req.header.SessionID)
	}

	// Decode Protocol Header
	// If Keys have been exchanged, use AES-CCM with the session's Encryption Key.
	if len(req.session.DecryptionKey) > 0 {
		if err := req.DecryptAndAuthenticate(req.session.DecryptionKey); err != nil {
			s.network.logger.Warn("failed to decrypt and authenticate", "error", err)
			return err
		}
	} else {
		if err := req.DecodeProtocolHeader(); err != nil {
			s.network.logger.Warn("failed to decode protocol header", "error", err)
			return err
		}
	}

	// ProcessMessageCounter
	// The decrypted Message Counter is validated against the sender's `MessageReceptionState` sliding window.
	if err := req.ProcessMessageCounter(); err != nil {
		if err == ErrDuplicateMessage && (req.protocolHeader.ExchangeFlags&FlagReliable) != 0 {
			s.mrp.sendStandaloneAck(req)
		}
		s.network.logger.Warn("replay detected or invalid counter", "error", err)
		return err
	}

	// Handle ACKs and Schedule ACK
	if (req.protocolHeader.ExchangeFlags & FlagAck) != 0 {
		s.mrp.acknowledgeMessage(req.protocolHeader.AckCounter)
	}
	if (req.protocolHeader.ExchangeFlags & FlagReliable) != 0 {
		s.mrp.scheduleAck(req)
	}

	return nil
}
