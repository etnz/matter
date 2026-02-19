# `matter` Module Development Roadmap

## Phase 1: The Naked Transport (Plain Text & Routing)
**Goal:** Establish the foundational UDP-like architecture using an in-memory connection. The Client sends a raw string, the Server receives it, wraps it in context, and the Handler replies. 

* **The Mock Transport:** Build `MockPacketConn` using Go channels to implement `net.PacketConn`. This simulates a network without opening actual ports.
* **The Server & Client Loops:** Build the `matter.Server` and `matter.Client` with a `context.Context` aware listener loop that continuously calls `ReadFrom()`.
* **The Router & Context:** Implement the `ServeMux` and `ExchangeContext`. When a packet arrives, the server routes the plaintext bytes to your handler.
* **The Test:** The Client sends `"PING"`, and the Server successfully triggers your mock handler and routes `"PONG"` back to the client.

## Phase 2: Introducing the Interaction Model (TLV)
**Goal:** Swap out the plain text for Matter-compliant TLV payloads using the `mattertlv` package.

* **Message Framing:** Introduce unencrypted `MessageHeader` and `ProtocolHeader` structs so the Server can extract an `ExchangeID`.
* **TLV Encoding/Decoding:** Update the Client to send a properly encoded `ReadRequest` using `gomat`'s `TLVBuffer`. Update the Server to decode this using `mattertlv.Decode()`.
* **The Test:** The Client sends an encoded `InvokeRequest`. The Server parses the TLV, routes it based on the Cluster ID, and replies with an `InvokeResponse`.

## Phase 3: Message Reliability Protocol (MRP)
**Goal:** Introduce the state machines that guarantee delivery. 

* **Message Counters:** Implement incrementing counters for every outbound message.
* **The ACK Engine:** Before passing a payload to the handler, check the `ProtocolHeader`. If the `AckRequest` flag is set, immediately write a standalone ACK packet back to the network.
* **Retries & Timeouts (SED Support):** Implement a retry buffer in the `ExchangeContext` that respects `ActiveInterval` and `IdleInterval` timeouts for sleeping devices.
* **The Test:** Update `MockPacketConn` to intentionally drop 50% of the packets. Assert that the Client and Server complete a TLV exchange relying purely on the MRP retry engine.

## Phase 4: PASE (SPAKE2+) Handshakes via Interfaces
**Goal:** Introduce the PIN-based authentication phase using dependency injection, allowing us to test the state machine with fake math before using real cryptography. 

* **The Interface:** Define the `PASEEngine` interface:
  ```go
  type PASEEngine interface {
      GeneratePBKDFResponse(req []byte) (salt []byte, iterations int)
      GeneratePAKE1(pin uint32) (x []byte)
      ProcessPAKE1AndGeneratePAKE2(x []byte) (y []byte, serverMAC []byte)
      VerifyPAKE3(clientMAC []byte) (encryptKey, decryptKey []byte, err error)
  }
  ```
* **The Fake Implementation:** Create `FakePASEEngine` where `PAKE1` just returns the string `"FAKE_X"`, and `VerifyPAKE3` just returns hardcoded `[16]byte` keys.
* **The State Machines:** Build the Client (Initiator) and Server (Responder) state machines in your listen loop to handle Opcodes `0x20` to `0x24`.
* **The Test:** Use the `FakePASEEngine` to assert the Client and Server exchange the 4 handshake messages in the correct order and generate a session. Once tests pass, swap in `gomat`'s elliptic curve math as the `RealPASEEngine` and re-test.

## Phase 5: CASE (SIGMA) & Certificate Management
**Goal:** Implement the final identity layer using the same interface-driven approach for device certificates.

* **The Interface:** Define the `CASEEngine` interface:
  ```go
  type CASEEngine interface {
      GenerateSigma1() (ephemeralKey []byte)
      ProcessSigma1AndGenerateSigma2(clientKey []byte) (serverKey, noc, signature []byte)
      ProcessSigma2AndGenerateSigma3(serverKey, noc, signature []byte) (clientNoc, clientSig []byte, err error)
  }
  ```
* **The Fake Implementation:** Create `FakeCASEEngine` that skips certificate math and just returns dummy byte arrays.
* **The Keystore:** Port over `gomat`'s Fabric logic so the Server and Client can load their Node Operational Certificates (NOC).
* **The Test:** Verify the SIGMA routing using the fake engine. Once the 3-step routing works, plug in the real `crypto/ecdh` and `crypto/ecdsa` math to verify real certificates and establish a secure session.