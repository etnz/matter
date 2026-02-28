# Architecture Overview: Matter Protocol Implementation in Go

This document describes the core architecture of the `github.com/etnz/matter` repository, a Go implementation of the Matter protocol. The implementation follows a layered approach, separating network transport, security handshakes, and the high-level Interaction Model.

## Core Messaging Layer
The messaging layer handles the construction and parsing of Matter packets, which consist of multiple nested headers and a payload.

* **`Message`**: Represents a high-level application message containing a `ProtocolID` (e.g., Secure Channel, Interaction Model), an `OpCode`, and a binary payload.
* **`packet`**: The internal structure used to move data through the stack. It encapsulates the unencrypted Message Header and the Protocol Header, which is encrypted during secure sessions.
* **TLV (Tag-Length-Value)**: Matter uses a custom binary encoding format. This package provides a full implementation for encoding and decoding complex nested structures, arrays, and lists used throughout the protocol.

## Message Reliability Protocol (MRP)
The MRP layer guarantees message delivery over unreliable transports (UDP).
* **Engine**: The `mrpEngine` runs asynchronously, managing `RetransmissionTable` and `AckTable`.
* **Reliability**: Implements exponential backoff for retransmissions.
* **Acknowledgements**: Supports both Piggybacked ACKs (embedded in response) and Standalone ACKs (generated if no response is ready).

## Secure Channel and Session Management
Security is central to Matter, establishing encrypted sessions between nodes.

* **Handshake Protocols**:
    * **PASE**: Passcode-Authenticated Session Establishment. It is used exclusively during commissioning to establish the first secure session using a numeric passcode.
    * **CASE**: Certificate-Authenticated Session Establishment. It is used for operational communication between commissioned nodes using X.509 certificates.
* **`Fabric`**: Represents a logical grouping of nodes that share a trusted root. It manages certificates and the Intermediate Public Key (IPK).
* **`SessionContext`**: Maintains the state for an active encrypted session, including session IDs, message counters for replay protection, and AES-CCM encryption/decryption keys.
* **Status Reporting**: Implements the standardized Status Report message format used for session errors, termination, and acknowledgments.

## Communication Roles
The repository provides two primary entry points for interacting with the protocol.

### The Client
The `Client` struct initiates requests to a peer node.
* **Bootstrapping**: Supports establishing security via CASE (`ConnectWithFabric`) or PASE (`ConnectWithPasscode`) before sending data.
* **Flows**: Manages the `outboundFlow` for assigning counters and encryption, and the `inboundFlow` for decryption and matching responses to requests.
* **Interaction Helpers**: Provides high-level methods like `Read`, `Write`, `Invoke`, and `Subscribe` to simplify transactions.

### The Server
The `Server` struct listens for incoming UDP packets and routes them to appropriate handlers.
* **Session Resolution**: Identifies the session context for incoming packets to decrypt payloads correctly.
* **Handshake Automation**: Internally manages PASE and CASE state machines when initiation packets are received.
* **Dispatching**: Routes Interaction Model requests to user-defined callback functions such as `ReadHandler` or `InvokeHandler`.

## Interaction Model
This component implements the high-level language Matter nodes use for communication.
* **Information Blocks (IBs)**: Reusable components like `AttributePathIB` and `CommandPathIB` define coordinates (Endpoint, Cluster, Attribute/Command) for an action.
* **Standard Messages**: Implements TLV structures for core actions including Read/Report for attribute data, Write for modifications, Invoke for cluster commands, and Subscribe for periodic reporting.

## Data Model
The `dm/` directory contains the generated representation of the Matter Data Model.
* **Cluster Definitions**: Each sub-package (e.g., `oo` for On/Off, `lvl` for Level Control) contains Go types and constants for that cluster's attributes, commands, and enums.
* **Code Generation**: A tool (`dmgen`) parses XML cluster definitions and automatically generates Go structs and TLV logic.
* **Global Types**: Defines standard Matter types used across all clusters, such as `NodeID`, `FabricID`, and `EndpointID`.

## Network Transport
* **`network`**: A low-level abstraction that handles UDP socket read/write loops. It uses Go channels to pass packets to upper layers.
* **Mock Network**: Provides a virtualized network environment for testing client-server interactions without requiring actual UDP sockets.
```