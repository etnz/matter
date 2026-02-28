# Essential Developer Experience (UX) Enablers

This document covers features the package **must provide** to offer a high-quality, frictionless developer experience for users writing Matter devices or controllers.

## Zero-Configuration Discovery (mDNS / DNS-SD)
* **Full Broadcasting Implementation**: The package must provide the complete implementation for broadcasting Matter mDNS records (likely wrapping a 3rd party Go mDNS library). It must automatically publish and manage the `_matterc._udp` (Commissioning) and `_matter._tcp` (Operational) records without requiring the user to build this from scratch.

## Persistence / NVS Enablement
* **Standardized Storage Interfaces**: While the package won't enforce a specific database, it must provide robust, well-defined Go interfaces (e.g., `SaveFabric`, `LoadFabric`, `SaveGroupKeys`, `SaveACLs`) so a user can effortlessly plug in their own Non-Volatile Storage (NVS) backend.

## Network Provisioning Hooks
* **Standardized Callbacks**: Provide clean callback interfaces (e.g., `OnJoinWiFi(ssid, password)`, `OnJoinThread(dataset)`) triggered by the Network Commissioning Cluster. This creates a clear bridge between the Matter protocol's data model and the user's OS-level networking logic.

## Setup Payload Generator
* **URI & QR Code Helper**: Provide a utility function that takes the device's Passcode, Vendor ID, Product ID, and Discriminator, and outputs the standard Matter Setup Payload URI (`MT:...`). This makes it trivial for the user to render a pairing QR code or display a manual pairing code.