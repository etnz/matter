# Missing Core Protocol Compliance

This document outlines the features and fixes required within the core Matter package (the protocol stack itself) to achieve compliance with the Matter specification. 

## Cryptography and Security (CASE/PASE)
* **Real Signatures in CASE**: Replace the dummy signature logic in `securechannel/case.go`. Implement proper ECDSA signature generation and verification in `generateSigma2` and `generateSigma3` to ensure actual node identity verification.
* **Certificate Serialization**: Update `SerializeCertificateIntoMatter` in `securechannel/fabric.go` to properly encode X.509 certificates into Matter's specific TLV structure for Node Operational Certificates (NOCs), rather than returning raw DER bytes.
* **Privacy Obfuscation**: Implement AES-CTR encryption in `packet.go` (`ApplyPrivacyObfuscation` and `RemovePrivacyObfuscation`) to encrypt message headers (Message Counter, Node IDs) as required by the specification to prevent device tracking.

## Interaction Model (IM) Deficiencies
* **Message Chunking**: Implement `NewChunkedResponse` in `packet.go` to support breaking down large payloads (like extensive `ReportData` lists) that exceed the IPv6 Maximum Transmission Unit (MTU).
* **Status Reporting**: Fix the `NewStatusReport` stub to correctly construct the `StatusReport` payload, assign the accurate Exchange ID, flip the Initiator flag, and set the protocol opcode to `OpCodeStatusReport`.
* **Subscription Engine**: Build a background engine to support `SubscribeRequest`. This engine must manage timers (`MinIntervalFloor`, `MaxIntervalCeiling`) and actively push `ReportDataMessage` updates to the client when attribute values change.
* **Message Routing Engine**: Implement an internal dispatcher in the `Server` that routes incoming `AttributePathIB` requests (Reads/Writes/Invokes) to the correct user-defined Endpoints and Clusters.

## Transports & Sessions
* **TCP Framing**: Implement the length-prepended framing logic in `EncodeFraming` for TCP transport, which is required for Bulk Data Exchange (BDX) and specific commissioning scenarios.
* **Session Lifecycle Management**: Add logic to properly manage sessions stored in `sync.Map`, including session eviction, keep-alive tracking, and session resumption (`CASESigma2Resume`).

## Addendums
* **MRP Implementation**: Implemented the `mrpEngine` to handle reliable messaging over UDP. This includes the `RetransmissionTable`, `AckTable`, exponential backoff logic, and support for both Piggybacked and Standalone Acknowledgements.