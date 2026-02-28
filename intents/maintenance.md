# Maintenance & Verification

This document captures technical debt, tooling improvements, and verification tasks required to mature the codebase.

## Technical Debt
* **Standard CCM Implementation**: Replace the temporary `github.com/tom-code/gomat/ccm` dependency with the standard library version once the relevant Go proposal (issue #27484) is implemented.

## Tooling & Documentation
* **Data Model Generator**: Update `dmgen` to handle inheritance trees for derived clusters. It must resolve underlying data types owned by base cluster specifications instead of ignoring them.
* **Package Documentation**: Write comprehensive GoDoc for the main `matter` package, replacing the current placeholder.

## Verification
* **CHIP Tool Validation**: Validate PASE/CASE handshakes and Interaction Model messages against `chip-tool` and `chip-all-clusters-app`.
* **Cross-Fabric Commissioning**: Verify commissioning of the Go server into real-world ecosystems (Apple Home, Google Home, Home Assistant).