# Matter (Go)

> **⚠️ Status: Under Development**
> This project is currently a work in progress and has **not yet reached compliance** with the Matter specification.
> We are actively working towards it, and **contributions are welcome!**

## 🔭 Product Vision & Intents
We are building a compliant, idiomatic Go implementation of the Matter protocol. **Our goal is to let developers easily write Matter devices or controllers in Go.**

To achieve this, the core library manages the complex protocol stack, while the developer provides the platform-specific glue (see **[Out of Scope](./intents/out-of-scope.md)**):
* **Business Logic**: Actual hardware actuation and sensor readings.
* **Network & BLE**: OS-level provisioning and Bluetooth advertisements.
* **Persistence**: A storage backend (NVS) implementation.
* **Security**: Secure storage for device attestation certificates.

## 🧭 Architecture
The system is designed as a layered protocol stack in Go.
* **Core Messaging**: Handles packet framing and TLV encoding.
* **Secure Channel**: Manages encryption and session establishment (PASE/CASE).
* **Interaction Model**: Implements the high-level language of Matter (Read/Write/Invoke).
* **[The Blueprint](./Blueprint.md)**: The spatial source of truth and detailed architectural map.

## 🎯 The Intents
An Intent captures a desired evolution.

### Active Intents
* **[Compliance](./intents/compliance.md)**: Missing core protocol features (Crypto, MRP, IM).
* **[Experience](./intents/experience.md)**: Developer UX (mDNS, NVS, Callbacks).
* **[Maintenance](./intents/maintenance.md)**: Technical debt, tooling, and verification tasks.

### Research & Boundaries
* **[Undecided](./intents/undecided.md)**: Areas requiring further investigation (ACLs, BTP).
* **[Out of Scope](./intents/out-of-scope.md)**: Features explicitly excluded from the core package.

## 📅 Release Plan
* **Current Focus**: Achieving core protocol compliance and passing `chip-tool` validation.

