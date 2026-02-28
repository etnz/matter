# Out of Scope for Core Package

This document outlines elements that are strictly the responsibility of the application, the operating system, or the hardware. The core Matter package will **not** attempt to abstract these generically, though optional convenience implementations may be provided.

## Cluster Business Logic
* **Hardware Actuation & Sensing**: The user must provide the actual code that executes cluster commands (e.g., flipping a physical GPIO relay for the `OnOff` cluster, or reading an I2C bus for the `TemperatureMeasurement` cluster).

## Hardware Security Extraction
* **Secure Enclave Integration**: The code required to physically extract or use the Device Attestation Certificate (DAC), Product Attestation Intermediate (PAI), and Certificate Declaration (CD) from a hardware TrustZone or secure element is strictly up to the hardware manufacturer.

## OS-Level Network & BLE Management
* **Actual Device Provisioning**: The core stack will not include the OS-specific commands (like `wpa_supplicant`, `nmcli`, or `OpenThread` CLI) to connect the device to a router.
* **BLE Advertisement & Connections**: Opening, managing, and advertising Bluetooth Low Energy connections using OS APIs (like BlueZ on Linux or CoreBluetooth on macOS) is outside the core stack.
* *Note on Convenience Implementations:* The project **may** provide reference/helper packages specifically for Linux (e.g., a Linux BLE advertiser, a Linux Wi-Fi provisioner, or a Thread border router integration) to help users get started quickly.

## NVS Engine Implementation
* **Database Engine**: The core package will not bundle a heavy database (like SQLite). The user is expected to implement a storage interface.
* *Note on Convenience Implementations:* The project **may** provide a very basic, simple file-based JSON/KV implementation out-of-the-box for rapid prototyping and testing.