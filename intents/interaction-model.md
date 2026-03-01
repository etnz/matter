

# Interaction Model (IM)

The Interaction Model (IM) defines the "language" that Matter nodes use to communicate. It sits above the secure channel and transport layers, providing a unified way to interact with the Data Model (Clusters, Attributes, Commands, and Events).

This document details the architectural flow and requirements for implementing the Interaction Model layer, specifically focusing on how the server processes incoming requests before dispatching them to the application logic.

## Commands

When a Matter server receives an Interaction Model (IM) message—specifically an **Invoke Request Action** intended to trigger a command—the Interaction Model layer acts as a strict gatekeeper. It performs a series of validations, security checks, and data verifications before it ever hands the data over to the manufacturer's specific application code (the callback).

Here is exactly what the server implementation is required to do between receiving the IM message and executing the manufacturer's code:

**1. Transaction and Timing Validation**
The server first checks the context of the transaction. If the command requires a Timed Invoke (a security measure to prevent replay attacks), the server verifies that a prior `Timed Request Action` was successfully received and that the defined timeout interval has not expired. 

**2. Path Resolution and Verification**
The IM message contains a list of requests (`InvokeRequests`), each specifying a `CommandPathIB` that targets a specific Endpoint, Cluster, and Command ID.
*   If the path uses wildcards, the server expands it into a list of concrete paths.
*   For each concrete path, the server checks its internal data model hierarchy to ensure the destination actually exists. It will immediately reject the request and generate an error status if it targets an unsupported node (`UNSUPPORTED_NODE`), an unsupported endpoint (`UNSUPPORTED_ENDPOINT`), an unsupported cluster (`UNSUPPORTED_CLUSTER`), or an unsupported command (`UNSUPPORTED_COMMAND`).

**3. Access Control (ACL) Enforcement**
Before executing the command, the server must evaluate the requester's privileges using the Access Control Cluster.
*   The server uses the incoming message's metadata to derive an Incoming Subject Descriptor (ISD), which identifies the sender and their authentication mode (e.g., a secure CASE session or a Group cast).
*   It checks the Node's Access Control List (ACL) and Access Restriction List (ARL) to verify if the sender has been granted the required privilege level (such as `Operate` or `Manage`) to invoke that specific command on that specific cluster.
*   If the sender lacks privileges, or if the device is in a managed state that restricts the action, the server aborts the process and returns an `UNSUPPORTED_ACCESS` or `ACCESS_RESTRICTED` error.

**4. Payload Constraint Checking**
If the path exists and access is granted, the server decodes the `CommandFields` (the arguments) provided in the message. The IM layer is responsible for validating the payload against the strict constraints defined in the cluster specification:
*   If a mandatory data field is missing, or if the incoming data cannot be mapped to the expected data type, the server must generate an `INVALID_COMMAND` error.
*   If the data violates expected constraints (e.g., an integer is out of the allowed range or a string is too long), the server should generate a `CONSTRAINT_ERROR`.

**5. Execution (The Manufacturer Callback)**
Only after the message passes all of the above rigorous IM layer checks is it dispatched to the **Invoke Execution** phase. This is the exact point where the protocol stack hands off control to the manufacturer-written callback code. The application code receives the pre-validated data and performs the actual physical or logical behavior (e.g., turning on a pump, modifying an energy forecast, or rotating a disco ball).

**6. Response Generation**
Once the manufacturer's callback code finishes executing, it returns its result to the IM layer. The server then constructs an **Invoke Response Action**. Depending on the cluster specification, this response will be encoded as either:
*   A `CommandStatusIB` containing a simple `SUCCESS` status or a cluster-specific failure status.
*   A `CommandDataIB` containing a specific response command payload (if the command is designed to return data back to the client).

Finally, the IM layer packages this response and submits it to the message layer to be transmitted back to the client.

## Events

Unlike commands, which flow from the client to the server, **events flow in the opposite direction**—from the server's manufacturer application code back to the client. 

Instead of executing a specific callback upon receiving a message, the server implementation's role for events is to capture them from the application, manage their storage, evaluate client access, and securely deliver them via the Interaction Model (IM).

Here is exactly what the server implementation is required to do to manage events:

**1. Event Generation and Buffering (Application to IM Layer)**
When the manufacturer's application code detects a specific occurrence (e.g., a hardware fault, a button press, or a completed operation), it generates an event record and hands it to the IM layer.
*   **Numbering & Timestamps:** The server automatically tags each event with a timestamp (System or Epoch time) and a monotonically increasing Event Number (`event-no`) to ensure chronological ordering.
*   **Priority & Buffering:** The server places the event into an internal buffer based on its priority (`DEBUG`, `INFO`, or `CRITICAL`). If the buffer runs out of space, the server will prioritize retaining higher-priority events, and newer events will overwrite older ones within the same priority level.

**2. Client Request Processing**
Clients cannot "invoke" an event; instead, they retrieve them using either a **Read Interaction** (a one-time query) or a **Subscribe Interaction** (an ongoing request for updates). When the server receives a request for events, the IM layer acts as a gatekeeper:

*   **Path Resolution & Validation:** The server checks the requested path. It will reject the request with specific errors if it targets an unsupported node (`UNSUPPORTED_NODE`), endpoint (`UNSUPPORTED_ENDPOINT`), cluster (`UNSUPPORTED_CLUSTER`), or event (`UNSUPPORTED_EVENT`).
*   **Access Control (ACL) Enforcement:** The server evaluates the client's Incoming Subject Descriptor (ISD) against the Access Control List. The client must be granted the appropriate privilege (typically `View` privilege) to read events from that specific cluster. If access is denied or restricted by an Access Restriction List (ARL), the server generates an `UNSUPPORTED_ACCESS` or `ACCESS_RESTRICTED` error.

**3. Filtering and Scoping**
If access is granted, the IM layer filters the internal event buffer to determine exactly what the client is allowed to see:
*   **Event Number Filtering:** The server applies any `EventFilters` provided by the client, allowing the client to only request events that have an event number greater than a specific `EventMin` (so it doesn't receive duplicates of events it already has).
*   **Fabric-Sensitive Filtering:** If an event is designated as "fabric-sensitive," the server will strictly verify that the fabric associated with the event matches the accessing fabric of the client. If they do not match, the event is silently dropped from the report.

**4. Delivery (Report Data Generation)**
Once the events are validated and filtered, the server constructs a **Report Data Action** to transmit the data back to the client. 
*   **For a Read Interaction:** The server immediately sends the matched events queued in the buffer, ordered from lowest to highest event number, and the transaction is complete.
*   **For a Subscribe Interaction:** The server establishes a continuous reporting session. The delivery timing depends on the event's urgency. If the client flagged the event path as `IsUrgent`, the generation of this event will automatically trigger an immediate `Report Data` transmission (subject to a negotiated minimum interval). If it is not urgent, the server will simply queue it and deliver it opportunistically or during the next maximum interval heartbeat.

## Attributes

In the Matter Data Model, attributes represent the **persistent state, physical quantities, or configuration** of a device,,. Because attributes represent state rather than instantaneous occurrences (like events) or actions (like commands), the flow of how they are handled by the Interaction Model (IM) and the server is uniquely divided into three main interactions: **Read**, **Write**, and **Subscribe**.

Just like with commands and events, the Matter server's IM layer acts as a strict gatekeeper before interacting with the manufacturer’s underlying application code. 

Here is the exact flow for how attributes are processed:

### 1. The Write Flow (Modifying State)
When a client wants to change a device's state (e.g., changing a thermostat's setpoint), it initiates a **Write Interaction**.
*   **The Request:** The client sends a `Write Request Action` containing the targeted attribute paths and the new data values.
*   **Validation & Security:** The IM layer intercepts this and performs rigorous checks:
    *   **ACL Enforcement:** It verifies that the client has the necessary privilege (typically `Operate` for operational state, or `Manage` for configuration) to modify that specific attribute. If not, it generates an `UNSUPPORTED_ACCESS` error.
    *   **Timed Write Check:** If the attribute is flagged as security-sensitive (having the "Timed Interaction" quality), the server verifies that a strict time-window was successfully opened prior to the write. If not, it rejects it,.
    *   **Data Constraints:** The IM layer checks the incoming payload against the strict data types and constraints defined in the cluster (e.g., verifying a percentage is between 0 and 100). Violations result in a `CONSTRAINT_ERROR`.
    *   **Data Versioning:** The client can optionally send a "held data version" to ensure they are only overwriting the attribute if its state hasn't changed since they last looked. If the version mismatches, the server rejects it,.
*   **Execution (Manufacturer Callback):** Once validated, the IM layer passes the new value down to the manufacturer's application code. The application applies the physical or logical change. 
*   **Atomic Writes:** Matter also supports an "Atomic Write" flow for attributes, allowing a client to queue multiple attribute changes and apply them all at once (or roll them back) using `AtomicRequest` commands,.
*   **Response:** The server returns a `Write Response Action` confirming success or failure for each requested attribute,.

### 2. The Read Flow (Querying State)
When a client wants to know the current state of a device, it initiates a **Read Interaction**.
*   **The Request:** The client sends a `Read Request Action` specifying the exact attributes it wants, which can include wildcards (e.g., "give me all attributes on Endpoint 1"),.
*   **Filtering & Access:** 
    *   The server expands any wildcards into concrete paths.
    *   It checks the Access Control List (ACL) to ensure the client has at least `View` privilege for each attribute,. Unprivileged paths are silently dropped or return an error.
    *   **Data Version Filtering:** If the client provides a cluster data version it already knows, the server will omit the data if the version hasn't changed, saving network bandwidth.
*   **Response:** The server queries the manufacturer's application code for the current values, packages them into `AttributeDataIB` blocks, and sends them back in a `Report Data Action`,.

### 3. The Subscribe Flow (Asynchronous Updates)
Instead of constantly polling with Read Requests, a client can initiate a **Subscribe Interaction** to keep a "digital twin" of the attribute data synchronized locally.
*   **Priming:** The client sends a `Subscribe Request Action`. The server validates it and immediately responds with a `Report Data Action` containing the current state of all requested attributes.
*   **Ongoing Reporting:** The server then establishes a continuous reporting session based on negotiated time intervals (Minimum and Maximum intervals),.
*   **Event-Driven Updates:** Whenever the manufacturer's application code changes the value of a subscribed attribute locally (e.g., someone physically turns the thermostat dial), the application notifies the IM layer. 
    *   The IM layer evaluates the "Minimum Interval" to ensure it doesn't flood the network with traffic.
    *   As soon as allowed, it sends a new `Report Data Action` to the subscriber with just the updated attribute values (the deltas).
*   **Quieter Reporting / Changes Omitted:** To prevent network flooding from rapidly fluctuating attributes (like live power draw in watts or a countdown timer), the IM layer applies data qualities like `Changes Omitted` or `Quieter Reporting`, explicitly filtering out meaningless intermediate deltas,.

## Implementation

Here is the list of extra requirements we are adding for the sake of coding.

- support tag based serialisation for tlv entities to drastically simplify the generation code.
- simplify the generation code out of a single main. It should have some real estate to make it more readable.
  - A full xml data object model is read in memory, with accessors corresponding to the queries that are required for the generation process.
  - Predefined Matter types and enum are defined in a map.
  - Generate a intermediate Go oriented representation (IR) of the data model (with package names, type names solved)
  - finally the last layer generates the Go text (or Go AST) from the IR.
  - The generated code should be minimalistic and leverage struct tags.
    - using tags for data types serialization to TLV. every data type is generated as a struct with tlv tags for their serialization.
    - a Cluster type (one per cluster) is generated with the following fields:
       - one field ID that has the cluster's ID, and a 'matter' tag for the extra cluster-level metadata.
       - one field Feature with the feature bitmap with a 'matter' tag for bit definition.
       - one field per attribute: validation, and permission are managed by the server, field uses a 'matter' tag for metadata (id, read, write, etc.). An 'Updated' function call could be made after a single write or after a batch of atomic writes.
       - one field per command: The type of the field is a func matching the call arguments. The field also uses 'matter' tag for metadata (response, access, feature bit, etc.) .
    - 'events': the generated cluster is **composed** with a server type that manages event subscription and exposes a single 'PushEvent' method. So that manufacturers can call it.
    - The Cluster's type has an in-memory representation of its tags, that is, by definition, the Cluster type IR. So that we have a IR -> struct (code gen) and introspection to IR code that can be tested once and for all. The server code uses that IR (populate with active fields) to actually make the calls.