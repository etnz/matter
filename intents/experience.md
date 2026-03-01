# Essential Developer Experience (UX) Enablers

This document covers features the package **must provide** to offer a high-quality, frictionless developer experience for users writing Matter devices or controllers.

## Zero-Configuration Discovery (mDNS / DNS-SD)
* **Full Broadcasting Implementation**: The package must provide the complete implementation for broadcasting Matter mDNS records (likely wrapping a 3rd party Go mDNS library). It must automatically publish and manage the `_matterc._udp` (Commissioning) and `_matter._tcp` (Operational) records without requiring the user to build this from scratch.

## Data Model Interfaces
* **Cluster Interfaces**: The generated data model code must define clear Go interfaces for each cluster (e.g., `OperationalCredentialsServer`, `GroupKeyManagementServer`). This allows users to inject their own business logic or persistence layer by simply implementing the interface.

## Reference Cluster Implementations
Instead of forcing the user to implement complex infrastructure clusters from scratch, the package should provide production-ready implementations for the "plumbing" clusters.

* **Network Commissioning (Linux)**: Provide a built-in implementation for Linux (wrapping `nmcli` or `wpa_supplicant`) to handle Wi-Fi scanning and connection.
* **General Commissioning**: Provide a full implementation handling the fail-safe timer, regulatory configuration, and commissioning lifecycle.
* **Operational Credentials**: Provide a default file-based implementation for managing the Node Operational Certificate (NOC) chain and trusted roots.

## Setup Payload Generator
* **URI & QR Code Helper**: Provide a utility function that takes the device's Passcode, Vendor ID, Product ID, and Discriminator, and outputs the standard Matter Setup Payload URI (`MT:...`). This makes it trivial for the user to render a pairing QR code or display a manual pairing code.