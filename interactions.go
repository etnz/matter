package matter

/*

The Matter Interaction Model (IM) defines a set of ten core messages used to perform all data model operations (reading, writing, subscribing, invoking commands). All of these messages are namespaced under the **`PROTOCOL_ID_INTERACTION_MODEL` (0x0001)** and use the standard Matter Vendor ID (`0x0000`).

These messages are encoded in the Application Payload of your `matter.Message` using Matter's Tag-Length-Value (TLV) format. Here is the comprehensive list of all IM Protocol Messages, their Opcodes, and their format specifications.

### 1. StatusResponseMessage (Opcode 0x01)
Used to convey a success or error status at the transaction level, or to acknowledge receipt of chunked data.
*   **Payload Format (TLV Structure):**
    *   `Status` (Context Tag 0): Unsigned Integer (8 bits) representing the global Interaction Model Status Code.

### 2. ReadRequestMessage (Opcode 0x02)
Initiates a Read transaction to request attribute and/or event data.
*   **Payload Format (TLV Structure):**
    *   `AttributeRequests` (Tag 0, Optional): Array of `AttributePathIB`.
    *   `EventRequests` (Tag 1, Optional): Array of `EventPathIB`.
    *   `EventFilters` (Tag 2, Optional): Array of `EventFilterIB`.
    *   `FabricFiltered` (Tag 3): Boolean indicating whether to filter fabric-scoped lists to the accessing fabric.
    *   `DataVersionFilters` (Tag 4, Optional): Array of `DataVersionFilterIB`.

### 3. SubscribeRequestMessage (Opcode 0x03)
Initiates a Subscribe interaction to establish a continuous reporting session for attribute and/or event data.
*   **Payload Format (TLV Structure):**
    *   `KeepSubscriptions` (Tag 0): Boolean indicating if existing subscriptions should be kept.
    *   `MinIntervalFloor` (Tag 1): Unsigned Integer (16 bits) requested minimum interval.
    *   `MaxIntervalCeiling` (Tag 2): Unsigned Integer (16 bits) requested maximum interval.
    *   `AttributeRequests` (Tag 3, Optional): Array of `AttributePathIB`.
    *   `EventRequests` (Tag 4, Optional): Array of `EventPathIB`.
    *   `EventFilters` (Tag 5, Optional): Array of `EventFilterIB`.
    *   *(Note: Tag 6 is unused/reserved)*
    *   `FabricFiltered` (Tag 7): Boolean.
    *   `DataVersionFilters` (Tag 8, Optional): Array of `DataVersionFilterIB`.

### 4. SubscribeResponseMessage (Opcode 0x04)
Sent by the publisher to convey the final parameters and activate the subscription after all initial reports have been delivered.
*   **Payload Format (TLV Structure):**
    *   `SubscriptionID` (Tag 0): Unsigned Integer (32 bits).
    *   *(Note: Tag 1 is unused/reserved)*
    *   `MaxInterval` (Tag 2): Unsigned Integer (16 bits) representing the finalized maximum reporting interval.

### 5. ReportDataMessage (Opcode 0x05)
Sent to fulfill a Read Request or to send primed/periodic data for a Subscribe interaction.
*   **Payload Format (TLV Structure):**
    *   `SubscriptionID` (Tag 0, Optional): Unsigned Integer (32 bits). Present if part of a subscription.
    *   `AttributeReports` (Tag 1, Optional): Array of `AttributeReportIB`.
    *   `EventReports` (Tag 2, Optional): Array of `EventReportIB`.
    *   `MoreChunkedMessages` (Tag 3, Optional): Boolean. Set to true if the payload exceeds the MTU and more blocks are coming.
    *   `SuppressResponse` (Tag 4, Optional): Boolean.

### 6. WriteRequestMessage (Opcode 0x06)
Initiates a Write transaction to modify attribute data.
*   **Payload Format (TLV Structure):**
    *   `SuppressResponse` (Tag 0, Optional): Boolean.
    *   `TimedRequest` (Tag 1): Boolean indicating if this is part of a timed interaction.
    *   `WriteRequests` (Tag 2): Array of `AttributeDataIB` containing the paths and new values.
    *   `MoreChunkedMessages` (Tag 3, Optional): Boolean. Used if the write payload spans multiple messages.

### 7. WriteResponseMessage (Opcode 0x07)
Sent in response to a Write Request to indicate success or error for each requested path.
*   **Payload Format (TLV Structure):**
    *   `WriteResponses` (Tag 0): Array of `AttributeStatusIB` containing the status for each write path.

### 8. InvokeRequestMessage (Opcode 0x08)
Initiates an Invoke transaction to execute one or more cluster commands.
*   **Payload Format (TLV Structure):**
    *   `SuppressResponse` (Tag 0): Boolean.
    *   `TimedRequest` (Tag 1): Boolean indicating if this is part of a timed interaction.
    *   `InvokeRequests` (Tag 2): Array of `CommandDataIB` containing the command paths and arguments.

### 9. InvokeResponseMessage (Opcode 0x09)
Sent in response to an Invoke Request to provide command execution status or return data.
*   **Payload Format (TLV Structure):**
    *   `SuppressResponse` (Tag 0): Boolean.
    *   `InvokeResponses` (Tag 1): Array of `InvokeResponseIB` containing the returned data or status for each invoked command.
    *   `MoreChunkedMessages` (Tag 2): Boolean.

### 10. TimedRequestMessage (Opcode 0x0A)
Sent as a precursor to a Write Request or Invoke Request to establish a timed window (preventing intercept-and-replay attacks).
*   **Payload Format (TLV Structure):**
    *   `Timeout` (Tag 0): Unsigned Integer (16 bits) defining the time interval in milliseconds within which the subsequent message must arrive.

### Note on Information Blocks (IBs)
You will notice that these messages heavily reuse "Information Blocks" (like `AttributePathIB`, `EventDataIB`, `CommandDataIB`). These IBs are specifically designed to be encapsulated within TLV arrays so that your application layer can systematically unpack them, process each request/report iteratively, and build the respective Response Message using the same underlying struct types. Furthermore, for chunking (handling payloads exceeding the 1280 byte MTU), `ReportDataMessage`, `WriteRequestMessage`, and `InvokeResponseMessage` utilize the `MoreChunkedMessages` boolean to tell the receiver to await the next message chunk.

*/

import (
	"github.com/tom-code/gomat/mattertlv"
)

// StatusResponseMessage (Opcode 0x01)
// Used to convey a success or error status at the transaction level, or to acknowledge receipt of chunked data.
type StatusResponseMessage struct {
	Status uint8 // Tag 0: Unsigned Integer (8 bits) representing the global Interaction Model Status Code.
}

func (m *StatusResponseMessage) Encode() []byte {
	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteUInt8(0, m.Status)
	tlv.WriteStructEnd()
	return tlv.Bytes()
}

func (m *StatusResponseMessage) Decode(data []byte) error {
	tv := mattertlv.Decode(data)
	if val := tv.GetItemWithTag(0); val != nil {
		m.Status = uint8(val.GetInt())
	}
	return nil
}

// ReadRequestMessage (Opcode 0x02)
// Initiates a Read transaction to request attribute and/or event data.
type ReadRequestMessage struct {
	AttributeRequests  []AttributePathIB     // Tag 0, Optional: Array of AttributePathIB.
	EventRequests      []EventPathIB         // Tag 1, Optional: Array of EventPathIB.
	EventFilters       []EventFilterIB       // Tag 2, Optional: Array of EventFilterIB.
	FabricFiltered     bool                  // Tag 3: Boolean indicating whether to filter fabric-scoped lists to the accessing fabric.
	DataVersionFilters []DataVersionFilterIB // Tag 4, Optional: Array of DataVersionFilterIB.
}

func (m *ReadRequestMessage) Encode() []byte {
	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	if len(m.AttributeRequests) > 0 {
		tlv.WriteArray(0)
		for _, ib := range m.AttributeRequests {
			tlv.WriteAnonList()
			ib.Encode(&tlv)
			tlv.WriteStructEnd()
		}
		tlv.WriteStructEnd()
	}
	if len(m.EventRequests) > 0 {
		tlv.WriteArray(1)
		for _, ib := range m.EventRequests {
			tlv.WriteAnonList()
			ib.Encode(&tlv)
			tlv.WriteStructEnd()
		}
		tlv.WriteStructEnd()
	}
	if len(m.EventFilters) > 0 {
		tlv.WriteArray(2)
		for _, ib := range m.EventFilters {
			ib.Encode(&tlv)
		}
		tlv.WriteStructEnd()
	}
	tlv.WriteBool(3, m.FabricFiltered)
	if len(m.DataVersionFilters) > 0 {
		tlv.WriteArray(4)
		for _, ib := range m.DataVersionFilters {
			ib.Encode(&tlv)
		}
		tlv.WriteStructEnd()
	}
	tlv.WriteStructEnd()
	return tlv.Bytes()
}

func (m *ReadRequestMessage) Decode(data []byte) error {
	tv := mattertlv.Decode(data)
	if val := tv.GetItemWithTag(0); val != nil {
		for _, child := range val.GetChild() {
			var ib AttributePathIB
			ib.Decode(child)
			m.AttributeRequests = append(m.AttributeRequests, ib)
		}
	}
	if val := tv.GetItemWithTag(1); val != nil {
		for _, child := range val.GetChild() {
			var ib EventPathIB
			ib.Decode(child)
			m.EventRequests = append(m.EventRequests, ib)
		}
	}
	if val := tv.GetItemWithTag(2); val != nil {
		for _, child := range val.GetChild() {
			var ib EventFilterIB
			ib.Decode(child)
			m.EventFilters = append(m.EventFilters, ib)
		}
	}
	if val := tv.GetItemWithTag(3); val != nil {
		m.FabricFiltered = val.GetBool()
	}
	if val := tv.GetItemWithTag(4); val != nil {
		for _, child := range val.GetChild() {
			var ib DataVersionFilterIB
			ib.Decode(child)
			m.DataVersionFilters = append(m.DataVersionFilters, ib)
		}
	}
	return nil
}

// SubscribeRequestMessage (Opcode 0x03)
// Initiates a Subscribe interaction to establish a continuous reporting session for attribute and/or event data.
type SubscribeRequestMessage struct {
	KeepSubscriptions  bool                  // Tag 0: Boolean indicating if existing subscriptions should be kept.
	MinIntervalFloor   uint16                // Tag 1: Unsigned Integer (16 bits) requested minimum interval.
	MaxIntervalCeiling uint16                // Tag 2: Unsigned Integer (16 bits) requested maximum interval.
	AttributeRequests  []AttributePathIB     // Tag 3, Optional: Array of AttributePathIB.
	EventRequests      []EventPathIB         // Tag 4, Optional: Array of EventPathIB.
	EventFilters       []EventFilterIB       // Tag 5, Optional: Array of EventFilterIB.
	FabricFiltered     bool                  // Tag 7: Boolean.
	DataVersionFilters []DataVersionFilterIB // Tag 8, Optional: Array of DataVersionFilterIB.
}

func (m *SubscribeRequestMessage) Encode() []byte {
	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteBool(0, m.KeepSubscriptions)
	tlv.WriteUInt16(1, m.MinIntervalFloor)
	tlv.WriteUInt16(2, m.MaxIntervalCeiling)
	if len(m.AttributeRequests) > 0 {
		tlv.WriteArray(3)
		for _, ib := range m.AttributeRequests {
			tlv.WriteAnonList()
			ib.Encode(&tlv)
			tlv.WriteStructEnd()
		}
		tlv.WriteStructEnd()
	}
	if len(m.EventRequests) > 0 {
		tlv.WriteArray(4)
		for _, ib := range m.EventRequests {
			tlv.WriteAnonList()
			ib.Encode(&tlv)
			tlv.WriteStructEnd()
		}
		tlv.WriteStructEnd()
	}
	if len(m.EventFilters) > 0 {
		tlv.WriteArray(5)
		for _, ib := range m.EventFilters {
			ib.Encode(&tlv)
		}
		tlv.WriteStructEnd()
	}
	tlv.WriteBool(7, m.FabricFiltered)
	if len(m.DataVersionFilters) > 0 {
		tlv.WriteArray(8)
		for _, ib := range m.DataVersionFilters {
			ib.Encode(&tlv)
		}
		tlv.WriteStructEnd()
	}
	tlv.WriteStructEnd()
	return tlv.Bytes()
}

func (m *SubscribeRequestMessage) Decode(data []byte) error {
	tv := mattertlv.Decode(data)
	if val := tv.GetItemWithTag(0); val != nil {
		m.KeepSubscriptions = val.GetBool()
	}
	if val := tv.GetItemWithTag(1); val != nil {
		m.MinIntervalFloor = uint16(val.GetInt())
	}
	if val := tv.GetItemWithTag(2); val != nil {
		m.MaxIntervalCeiling = uint16(val.GetInt())
	}
	if val := tv.GetItemWithTag(3); val != nil {
		for _, child := range val.GetChild() {
			var ib AttributePathIB
			ib.Decode(child)
			m.AttributeRequests = append(m.AttributeRequests, ib)
		}
	}
	if val := tv.GetItemWithTag(4); val != nil {
		for _, child := range val.GetChild() {
			var ib EventPathIB
			ib.Decode(child)
			m.EventRequests = append(m.EventRequests, ib)
		}
	}
	if val := tv.GetItemWithTag(5); val != nil {
		for _, child := range val.GetChild() {
			var ib EventFilterIB
			ib.Decode(child)
			m.EventFilters = append(m.EventFilters, ib)
		}
	}
	if val := tv.GetItemWithTag(7); val != nil {
		m.FabricFiltered = val.GetBool()
	}
	if val := tv.GetItemWithTag(8); val != nil {
		for _, child := range val.GetChild() {
			var ib DataVersionFilterIB
			ib.Decode(child)
			m.DataVersionFilters = append(m.DataVersionFilters, ib)
		}
	}
	return nil
}

// SubscribeResponseMessage (Opcode 0x04)
// Sent by the publisher to convey the final parameters and activate the subscription after all initial reports have been delivered.
type SubscribeResponseMessage struct {
	SubscriptionID uint32 // Tag 0: Unsigned Integer (32 bits).
	MaxInterval    uint16 // Tag 2: Unsigned Integer (16 bits) representing the finalized maximum reporting interval.
}

func (m *SubscribeResponseMessage) Encode() []byte {
	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteUInt32(0, m.SubscriptionID)
	tlv.WriteUInt16(2, m.MaxInterval)
	tlv.WriteStructEnd()
	return tlv.Bytes()
}

func (m *SubscribeResponseMessage) Decode(data []byte) error {
	tv := mattertlv.Decode(data)
	if val := tv.GetItemWithTag(0); val != nil {
		m.SubscriptionID = uint32(val.GetInt())
	}
	if val := tv.GetItemWithTag(2); val != nil {
		m.MaxInterval = uint16(val.GetInt())
	}
	return nil
}

// ReportDataMessage (Opcode 0x05)
// Sent to fulfill a Read Request or to send primed/periodic data for a Subscribe interaction.
type ReportDataMessage struct {
	SubscriptionID      *uint32             // Tag 0, Optional: Unsigned Integer (32 bits). Present if part of a subscription.
	AttributeReports    []AttributeReportIB // Tag 1, Optional: Array of AttributeReportIB.
	EventReports        []EventReportIB     // Tag 2, Optional: Array of EventReportIB.
	MoreChunkedMessages bool                // Tag 3, Optional: Boolean. Set to true if the payload exceeds the MTU and more blocks are coming.
	SuppressResponse    bool                // Tag 4, Optional: Boolean.
}

func (m *ReportDataMessage) Encode() []byte {
	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	if m.SubscriptionID != nil {
		tlv.WriteUInt32(0, *m.SubscriptionID)
	}
	if len(m.AttributeReports) > 0 {
		tlv.WriteArray(1)
		for _, ib := range m.AttributeReports {
			ib.Encode(&tlv)
		}
		tlv.WriteStructEnd()
	}
	if len(m.EventReports) > 0 {
		tlv.WriteArray(2)
		for _, ib := range m.EventReports {
			ib.Encode(&tlv)
		}
		tlv.WriteStructEnd()
	}
	if m.MoreChunkedMessages {
		tlv.WriteBool(3, m.MoreChunkedMessages)
	}
	if m.SuppressResponse {
		tlv.WriteBool(4, m.SuppressResponse)
	}
	tlv.WriteStructEnd()
	return tlv.Bytes()
}

func (m *ReportDataMessage) Decode(data []byte) error {
	tv := mattertlv.Decode(data)
	if val := tv.GetItemWithTag(0); val != nil {
		id := uint32(val.GetInt())
		m.SubscriptionID = &id
	}
	if val := tv.GetItemWithTag(1); val != nil {
		for _, child := range val.GetChild() {
			var ib AttributeReportIB
			ib.Decode(child)
			m.AttributeReports = append(m.AttributeReports, ib)
		}
	}
	if val := tv.GetItemWithTag(2); val != nil {
		for _, child := range val.GetChild() {
			var ib EventReportIB
			ib.Decode(child)
			m.EventReports = append(m.EventReports, ib)
		}
	}
	if val := tv.GetItemWithTag(3); val != nil {
		m.MoreChunkedMessages = val.GetBool()
	}
	if val := tv.GetItemWithTag(4); val != nil {
		m.SuppressResponse = val.GetBool()
	}
	return nil
}

// WriteRequestMessage (Opcode 0x06)
// Initiates a Write transaction to modify attribute data.
type WriteRequestMessage struct {
	SuppressResponse    bool              // Tag 0, Optional: Boolean.
	TimedRequest        bool              // Tag 1: Boolean indicating if this is part of a timed interaction.
	WriteRequests       []AttributeDataIB // Tag 2: Array of AttributeDataIB containing the paths and new values.
	MoreChunkedMessages bool              // Tag 3, Optional: Boolean. Used if the write payload spans multiple messages.
}

func (m *WriteRequestMessage) Encode() []byte {
	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	if m.SuppressResponse {
		tlv.WriteBool(0, m.SuppressResponse)
	}
	if m.TimedRequest {
		tlv.WriteBool(1, m.TimedRequest)
	}
	if len(m.WriteRequests) > 0 {
		tlv.WriteArray(2)
		for _, ib := range m.WriteRequests {
			ib.Encode(&tlv)
		}
		tlv.WriteStructEnd()
	}
	if m.MoreChunkedMessages {
		tlv.WriteBool(3, m.MoreChunkedMessages)
	}
	tlv.WriteStructEnd()
	return tlv.Bytes()
}

func (m *WriteRequestMessage) Decode(data []byte) error {
	tv := mattertlv.Decode(data)
	if val := tv.GetItemWithTag(0); val != nil {
		m.SuppressResponse = val.GetBool()
	}
	if val := tv.GetItemWithTag(1); val != nil {
		m.TimedRequest = val.GetBool()
	}
	if val := tv.GetItemWithTag(2); val != nil {
		for _, child := range val.GetChild() {
			var ib AttributeDataIB
			ib.Decode(child)
			m.WriteRequests = append(m.WriteRequests, ib)
		}
	}
	if val := tv.GetItemWithTag(3); val != nil {
		m.MoreChunkedMessages = val.GetBool()
	}
	return nil
}

// WriteResponseMessage (Opcode 0x07)
// Sent in response to a Write Request to indicate success or error for each requested path.
type WriteResponseMessage struct {
	WriteResponses []AttributeStatusIB // Tag 0: Array of AttributeStatusIB containing the status for each write path.
}

func (m *WriteResponseMessage) Encode() []byte {
	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	if len(m.WriteResponses) > 0 {
		tlv.WriteArray(0)
		for _, ib := range m.WriteResponses {
			ib.Encode(&tlv)
		}
		tlv.WriteStructEnd()
	}
	tlv.WriteStructEnd()
	return tlv.Bytes()
}

func (m *WriteResponseMessage) Decode(data []byte) error {
	tv := mattertlv.Decode(data)
	if val := tv.GetItemWithTag(0); val != nil {
		for _, child := range val.GetChild() {
			var ib AttributeStatusIB
			ib.Decode(child)
			m.WriteResponses = append(m.WriteResponses, ib)
		}
	}
	return nil
}

// InvokeRequestMessage (Opcode 0x08)
// Initiates an Invoke transaction to execute one or more cluster commands.
type InvokeRequestMessage struct {
	SuppressResponse bool            // Tag 0: Boolean.
	TimedRequest     bool            // Tag 1: Boolean indicating if this is part of a timed interaction.
	InvokeRequests   []CommandDataIB // Tag 2: Array of CommandDataIB containing the command paths and arguments.
}

func (m *InvokeRequestMessage) Encode() []byte {
	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	if m.SuppressResponse {
		tlv.WriteBool(0, m.SuppressResponse)
	}
	if m.TimedRequest {
		tlv.WriteBool(1, m.TimedRequest)
	}
	if len(m.InvokeRequests) > 0 {
		tlv.WriteArray(2)
		for _, ib := range m.InvokeRequests {
			ib.Encode(&tlv)
		}
		tlv.WriteStructEnd()
	}
	tlv.WriteStructEnd()
	return tlv.Bytes()
}

func (m *InvokeRequestMessage) Decode(data []byte) error {
	tv := mattertlv.Decode(data)
	if val := tv.GetItemWithTag(0); val != nil {
		m.SuppressResponse = val.GetBool()
	}
	if val := tv.GetItemWithTag(1); val != nil {
		m.TimedRequest = val.GetBool()
	}
	if val := tv.GetItemWithTag(2); val != nil {
		for _, child := range val.GetChild() {
			var ib CommandDataIB
			ib.Decode(child)
			m.InvokeRequests = append(m.InvokeRequests, ib)
		}
	}
	return nil
}

// InvokeResponseMessage (Opcode 0x09)
// Sent in response to an Invoke Request to provide command execution status or return data.
type InvokeResponseMessage struct {
	SuppressResponse    bool               // Tag 0: Boolean.
	InvokeResponses     []InvokeResponseIB // Tag 1: Array of InvokeResponseIB containing the returned data or status for each invoked command.
	MoreChunkedMessages bool               // Tag 2: Boolean.
}

func (m *InvokeResponseMessage) Encode() []byte {
	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	if m.SuppressResponse {
		tlv.WriteBool(0, m.SuppressResponse)
	}
	if len(m.InvokeResponses) > 0 {
		tlv.WriteArray(1)
		for _, ib := range m.InvokeResponses {
			ib.Encode(&tlv)
		}
		tlv.WriteStructEnd()
	}
	if m.MoreChunkedMessages {
		tlv.WriteBool(2, m.MoreChunkedMessages)
	}
	tlv.WriteStructEnd()
	return tlv.Bytes()
}

func (m *InvokeResponseMessage) Decode(data []byte) error {
	tv := mattertlv.Decode(data)
	if val := tv.GetItemWithTag(0); val != nil {
		m.SuppressResponse = val.GetBool()
	}
	if val := tv.GetItemWithTag(1); val != nil {
		for _, child := range val.GetChild() {
			var ib InvokeResponseIB
			ib.Decode(child)
			m.InvokeResponses = append(m.InvokeResponses, ib)
		}
	}
	if val := tv.GetItemWithTag(2); val != nil {
		m.MoreChunkedMessages = val.GetBool()
	}
	return nil
}

// TimedRequestMessage (Opcode 0x0A)
// Sent as a precursor to a Write Request or Invoke Request to establish a timed window (preventing intercept-and-replay attacks).
type TimedRequestMessage struct {
	Timeout uint16 // Tag 0: Unsigned Integer (16 bits) defining the time interval in milliseconds within which the subsequent message must arrive.
}

func (m *TimedRequestMessage) Encode() []byte {
	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteUInt16(0, m.Timeout)
	tlv.WriteStructEnd()
	return tlv.Bytes()
}

func (m *TimedRequestMessage) Decode(data []byte) error {
	tv := mattertlv.Decode(data)
	if val := tv.GetItemWithTag(0); val != nil {
		m.Timeout = uint16(val.GetInt())
	}
	return nil
}

// IB structs

type ClusterPathIB struct {
	Node     *uint64
	Endpoint *uint16
	Cluster  *uint32
}

func (ib *ClusterPathIB) Encode(tlv *mattertlv.TLVBuffer) {
	if ib.Node != nil {
		tlv.WriteUInt64(0, *ib.Node)
	}
	if ib.Endpoint != nil {
		tlv.WriteUInt16(1, *ib.Endpoint)
	}
	if ib.Cluster != nil {
		tlv.WriteUInt32(2, *ib.Cluster)
	}
}

func (ib *ClusterPathIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		v := uint64(val.GetInt())
		ib.Node = &v
	}
	if val := tv.GetItemWithTag(1); val != nil {
		v := uint16(val.GetInt())
		ib.Endpoint = &v
	}
	if val := tv.GetItemWithTag(2); val != nil {
		v := uint32(val.GetInt())
		ib.Cluster = &v
	}
}

type AttributePathIB struct {
	EnableTagCompression *bool
	Node                 *uint64
	Endpoint             *uint16
	Cluster              *uint32
	Attribute            *uint32
	ListIndex            *uint16
	WildcardPathFlags    *uint32
}

func (ib *AttributePathIB) Encode(tlv *mattertlv.TLVBuffer) {
	if ib.EnableTagCompression != nil {
		tlv.WriteBool(0, *ib.EnableTagCompression)
	}
	if ib.Node != nil {
		tlv.WriteUInt64(1, *ib.Node)
	}
	if ib.Endpoint != nil {
		tlv.WriteUInt16(2, *ib.Endpoint)
	}
	if ib.Cluster != nil {
		tlv.WriteUInt32(3, *ib.Cluster)
	}
	if ib.Attribute != nil {
		tlv.WriteUInt32(4, *ib.Attribute)
	}
	if ib.ListIndex != nil {
		tlv.WriteUInt16(5, *ib.ListIndex)
	}
	if ib.WildcardPathFlags != nil {
		tlv.WriteUInt32(6, *ib.WildcardPathFlags)
	}
}

func (ib *AttributePathIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		v := val.GetBool()
		ib.EnableTagCompression = &v
	}
	if val := tv.GetItemWithTag(1); val != nil {
		v := uint64(val.GetInt())
		ib.Node = &v
	}
	if val := tv.GetItemWithTag(2); val != nil {
		v := uint16(val.GetInt())
		ib.Endpoint = &v
	}
	if val := tv.GetItemWithTag(3); val != nil {
		v := uint32(val.GetInt())
		ib.Cluster = &v
	}
	if val := tv.GetItemWithTag(4); val != nil {
		v := uint32(val.GetInt())
		ib.Attribute = &v
	}
	if val := tv.GetItemWithTag(5); val != nil {
		v := uint16(val.GetInt())
		ib.ListIndex = &v
	}
	if val := tv.GetItemWithTag(6); val != nil {
		v := uint32(val.GetInt())
		ib.WildcardPathFlags = &v
	}
}

type EventPathIB struct {
	Node     *uint64
	Endpoint *uint16
	Cluster  *uint32
	Event    *uint32
	IsUrgent *bool
}

func (ib *EventPathIB) Encode(tlv *mattertlv.TLVBuffer) {
	if ib.Node != nil {
		tlv.WriteUInt64(0, *ib.Node)
	}
	if ib.Endpoint != nil {
		tlv.WriteUInt16(1, *ib.Endpoint)
	}
	if ib.Cluster != nil {
		tlv.WriteUInt32(2, *ib.Cluster)
	}
	if ib.Event != nil {
		tlv.WriteUInt32(3, *ib.Event)
	}
	if ib.IsUrgent != nil {
		tlv.WriteBool(4, *ib.IsUrgent)
	}
}

func (ib *EventPathIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		v := uint64(val.GetInt())
		ib.Node = &v
	}
	if val := tv.GetItemWithTag(1); val != nil {
		v := uint16(val.GetInt())
		ib.Endpoint = &v
	}
	if val := tv.GetItemWithTag(2); val != nil {
		v := uint32(val.GetInt())
		ib.Cluster = &v
	}
	if val := tv.GetItemWithTag(3); val != nil {
		v := uint32(val.GetInt())
		ib.Event = &v
	}
	if val := tv.GetItemWithTag(4); val != nil {
		v := val.GetBool()
		ib.IsUrgent = &v
	}
}

type EventFilterIB struct {
	Node     *uint64
	EventMin uint64
}

func (ib *EventFilterIB) Encode(tlv *mattertlv.TLVBuffer) {
	tlv.WriteAnonStruct()
	if ib.Node != nil {
		tlv.WriteUInt64(0, *ib.Node)
	}
	tlv.WriteUInt64(1, ib.EventMin)
	tlv.WriteStructEnd()
}

func (ib *EventFilterIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		v := uint64(val.GetInt())
		ib.Node = &v
	}
	if val := tv.GetItemWithTag(1); val != nil {
		ib.EventMin = uint64(val.GetInt())
	}
}

type DataVersionFilterIB struct {
	Path        ClusterPathIB
	DataVersion uint32
}

func (ib *DataVersionFilterIB) Encode(tlv *mattertlv.TLVBuffer) {
	tlv.WriteAnonStruct()
	tlv.WriteList(0)
	ib.Path.Encode(tlv)
	tlv.WriteStructEnd()
	tlv.WriteUInt32(1, ib.DataVersion)
	tlv.WriteStructEnd()
}

func (ib *DataVersionFilterIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		ib.Path.Decode(*val)
	}
	if val := tv.GetItemWithTag(1); val != nil {
		ib.DataVersion = uint32(val.GetInt())
	}
}

type AttributeDataIB struct {
	DataVersion *uint32
	Path        AttributePathIB
	Data        any
}

func (ib *AttributeDataIB) Encode(tlv *mattertlv.TLVBuffer) {
	tlv.WriteAnonStruct()
	if ib.DataVersion != nil {
		tlv.WriteUInt32(0, *ib.DataVersion)
	}
	tlv.WriteList(1)
	ib.Path.Encode(tlv)
	tlv.WriteStructEnd()
	if ib.Data != nil {
		if b, ok := ib.Data.([]byte); ok {
			tlv.WriteRaw(b)
		}
	}
	tlv.WriteStructEnd()
}

func (ib *AttributeDataIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		v := uint32(val.GetInt())
		ib.DataVersion = &v
	}
	if val := tv.GetItemWithTag(1); val != nil {
		ib.Path.Decode(*val)
	}
	if val := tv.GetItemWithTag(2); val != nil {
		ib.Data = val
	}
}

type StatusIB struct {
	Status        *uint8
	ClusterStatus *uint8
}

func (ib *StatusIB) Encode(tlv *mattertlv.TLVBuffer) {
	if ib.Status != nil {
		tlv.WriteUInt8(0, *ib.Status)
	}
	if ib.ClusterStatus != nil {
		tlv.WriteUInt8(1, *ib.ClusterStatus)
	}
}

func (ib *StatusIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		v := uint8(val.GetInt())
		ib.Status = &v
	}
	if val := tv.GetItemWithTag(1); val != nil {
		v := uint8(val.GetInt())
		ib.ClusterStatus = &v
	}
}

type AttributeStatusIB struct {
	Path   AttributePathIB
	Status StatusIB
}

func (ib *AttributeStatusIB) Encode(tlv *mattertlv.TLVBuffer) {
	tlv.WriteAnonStruct()
	tlv.WriteList(0)
	ib.Path.Encode(tlv)
	tlv.WriteStructEnd()
	tlv.WriteStruct(1)
	ib.Status.Encode(tlv)
	tlv.WriteStructEnd()
	tlv.WriteStructEnd()
}

func (ib *AttributeStatusIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		ib.Path.Decode(*val)
	}
	if val := tv.GetItemWithTag(1); val != nil {
		ib.Status.Decode(*val)
	}
}

type AttributeReportIB struct {
	AttributeStatus *AttributeStatusIB
	AttributeData   *AttributeDataIB
}

func (ib *AttributeReportIB) Encode(tlv *mattertlv.TLVBuffer) {
	tlv.WriteAnonStruct()
	if ib.AttributeStatus != nil {
		tlv.WriteStruct(0)
		tlv.WriteList(0)
		ib.AttributeStatus.Path.Encode(tlv)
		tlv.WriteStructEnd()
		tlv.WriteStruct(1)
		ib.AttributeStatus.Status.Encode(tlv)
		tlv.WriteStructEnd()
		tlv.WriteStructEnd()
	} else if ib.AttributeData != nil {
		tlv.WriteStruct(1)
		if ib.AttributeData.DataVersion != nil {
			tlv.WriteUInt32(0, *ib.AttributeData.DataVersion)
		}
		tlv.WriteList(1)
		ib.AttributeData.Path.Encode(tlv)
		tlv.WriteStructEnd()
		tlv.WriteStructEnd()
	}
	tlv.WriteStructEnd()
}

func (ib *AttributeReportIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		ib.AttributeStatus = &AttributeStatusIB{}
		ib.AttributeStatus.Decode(*val)
	}
	if val := tv.GetItemWithTag(1); val != nil {
		ib.AttributeData = &AttributeDataIB{}
		ib.AttributeData.Decode(*val)
	}
}

type EventStatusIB struct {
	Path   EventPathIB
	Status StatusIB
}

func (ib *EventStatusIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		ib.Path.Decode(*val)
	}
	if val := tv.GetItemWithTag(1); val != nil {
		ib.Status.Decode(*val)
	}
}

type EventDataIB struct {
	Path        EventPathIB
	EventNumber uint64
	Priority    uint8
	Data        any
}

func (ib *EventDataIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		ib.Path.Decode(*val)
	}
	if val := tv.GetItemWithTag(1); val != nil {
		ib.EventNumber = uint64(val.GetInt())
	}
	if val := tv.GetItemWithTag(2); val != nil {
		ib.Priority = uint8(val.GetInt())
	}
	if val := tv.GetItemWithTag(7); val != nil {
		ib.Data = val
	}
}

type EventReportIB struct {
	EventStatus *EventStatusIB
	EventData   *EventDataIB
}

func (ib *EventReportIB) Encode(tlv *mattertlv.TLVBuffer) {
	tlv.WriteAnonStruct()
	if ib.EventStatus != nil {
		tlv.WriteStruct(0)
		tlv.WriteList(0)
		ib.EventStatus.Path.Encode(tlv)
		tlv.WriteStructEnd()
		tlv.WriteStruct(1)
		ib.EventStatus.Status.Encode(tlv)
		tlv.WriteStructEnd()
		tlv.WriteStructEnd()
	} else if ib.EventData != nil {
		tlv.WriteStruct(1)
		tlv.WriteList(0)
		ib.EventData.Path.Encode(tlv)
		tlv.WriteStructEnd()
		tlv.WriteUInt64(1, ib.EventData.EventNumber)
		tlv.WriteUInt8(2, ib.EventData.Priority)
		if ib.EventData.Data != nil {
			if b, ok := ib.EventData.Data.([]byte); ok {
				tlv.WriteRaw(b)
			}
		}
		tlv.WriteStructEnd()
	}
	tlv.WriteStructEnd()
}

func (ib *EventReportIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		ib.EventStatus = &EventStatusIB{}
		ib.EventStatus.Decode(*val)
	}
	if val := tv.GetItemWithTag(1); val != nil {
		ib.EventData = &EventDataIB{}
		ib.EventData.Decode(*val)
	}
}

type CommandPathIB struct {
	EndpointId *uint16
	ClusterId  *uint32
	CommandId  *uint32
}

func (ib *CommandPathIB) Encode(tlv *mattertlv.TLVBuffer) {
	if ib.EndpointId != nil {
		tlv.WriteUInt16(0, *ib.EndpointId)
	}
	if ib.ClusterId != nil {
		tlv.WriteUInt32(1, *ib.ClusterId)
	}
	if ib.CommandId != nil {
		tlv.WriteUInt32(2, *ib.CommandId)
	}
}

func (ib *CommandPathIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		v := uint16(val.GetInt())
		ib.EndpointId = &v
	}
	if val := tv.GetItemWithTag(1); val != nil {
		v := uint32(val.GetInt())
		ib.ClusterId = &v
	}
	if val := tv.GetItemWithTag(2); val != nil {
		v := uint32(val.GetInt())
		ib.CommandId = &v
	}
}

type CommandDataIB struct {
	Path   CommandPathIB
	Fields any
}

func (ib *CommandDataIB) Encode(tlv *mattertlv.TLVBuffer) {
	tlv.WriteAnonStruct()
	tlv.WriteList(0)
	ib.Path.Encode(tlv)
	tlv.WriteStructEnd()
	if ib.Fields != nil {
		if b, ok := ib.Fields.([]byte); ok {
			tlv.WriteRaw(b)
		}
	}
	tlv.WriteStructEnd()
}

func (ib *CommandDataIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		ib.Path.Decode(*val)
	}
	if val := tv.GetItemWithTag(1); val != nil {
		ib.Fields = val
	}
}

type CommandStatusIB struct {
	Path   CommandPathIB
	Status StatusIB
}

func (ib *CommandStatusIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		ib.Path.Decode(*val)
	}
	if val := tv.GetItemWithTag(1); val != nil {
		ib.Status.Decode(*val)
	}
}

type InvokeResponseIB struct {
	Command *CommandDataIB
	Status  *CommandStatusIB
}

func (ib *InvokeResponseIB) Encode(tlv *mattertlv.TLVBuffer) {
	tlv.WriteAnonStruct()
	if ib.Command != nil {
		tlv.WriteStruct(0)
		tlv.WriteList(0)
		ib.Command.Path.Encode(tlv)
		tlv.WriteStructEnd()
		tlv.WriteStructEnd()
	} else if ib.Status != nil {
		tlv.WriteStruct(1)
		tlv.WriteList(0)
		ib.Status.Path.Encode(tlv)
		tlv.WriteStructEnd()
		tlv.WriteStruct(1)
		ib.Status.Status.Encode(tlv)
		tlv.WriteStructEnd()
		tlv.WriteStructEnd()
	}
	tlv.WriteStructEnd()
}

func (ib *InvokeResponseIB) Decode(tv mattertlv.TlvItem) {
	if val := tv.GetItemWithTag(0); val != nil {
		ib.Command = &CommandDataIB{}
		ib.Command.Decode(*val)
	}
	if val := tv.GetItemWithTag(1); val != nil {
		ib.Status = &CommandStatusIB{}
		ib.Status.Decode(*val)
	}
}
