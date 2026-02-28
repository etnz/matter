# Areas for Investigation

This document details features that sit on the boundary between the protocol stack and the application. Further architectural investigation is required before deciding if they belong in the core package (Bucket 1) or should be left to the user (Bucket 2).

## Generic ACL Enforcement
* **Concept**: A middleware layer within the core package that intercepts incoming Interaction Model requests, validates the `SessionContext` (Subject ID) against the Access Control Lists (ACLs), and automatically rejects unauthorized access.
* **Investigation**: Can this be done in a highly efficient, entirely generic way that works across all possible data model paradigms without hindering the user's custom cluster logic?

## DAC/PAI/CD Certificate Manager
* **Concept**: A ready-to-use `CertificateManager` implementation structured directly around reading standard DAC, PAI, and CD files/byte arrays.
* **Investigation**: Does this align safely and perfectly with how actual manufacturers securely provision and store attestation materials in the factory? Will a file-based cert manager encourage bad security practices in production devices?

## BTP (Bluetooth Transport Protocol) Encapsulation
* **Concept**: Providing the Matter-specific BTP framing, segmentation, and reassembly logic within the package. The user would handle the OS-level BLE connection, pass the raw BLE payload bytes to the package, and the package would reconstruct the Matter messages.
* **Investigation**: What is the true complexity of the BTP state machine? Can it be cleanly decoupled from the OS BLE stack (e.g., handling MTU size negotiations and characteristic subscriptions abstractly)?