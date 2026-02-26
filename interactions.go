package matter

import (
	"bytes"
	"fmt"

	"github.com/etnz/matter/tlv"
)

// StatusResponseMessage conveys a success or error status at the transaction level, or to acknowledge receipt of chunked data.
type StatusResponseMessage struct {
	// Status is the global Interaction Model Status Code (8 bits).
	Status uint8
}

func (m *StatusResponseMessage) Encode() tlv.Struct {
	return tlv.Struct{
		tlv.ContextTag(0): uint64(m.Status),
	}
}

func (m *StatusResponseMessage) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		if u, ok := v.(uint64); ok {
			m.Status = uint8(u)
		}
	}
	return nil
}

// ReadRequestMessage initiates a Read transaction to request attribute and/or event data.
type ReadRequestMessage struct {
	// AttributeRequests is a list of AttributePathIBs (Tag 0).
	AttributeRequests []AttributePathIB
	// EventRequests is a list of EventPathIBs (Tag 1).
	EventRequests []EventPathIB
	// EventFilters is a list of EventFilterIBs (Tag 2).
	EventFilters []EventFilterIB
	// FabricFiltered indicates whether to filter fabric-scoped lists to the accessing fabric (Tag 3).
	FabricFiltered bool
	// DataVersionFilters is a list of DataVersionFilterIBs (Tag 4).
	DataVersionFilters []DataVersionFilterIB
}

func (m *ReadRequestMessage) Encode() tlv.Struct {
	s := tlv.Struct{
		tlv.ContextTag(3): m.FabricFiltered,
	}
	if len(m.AttributeRequests) > 0 {
		arr := make([]tlv.List, len(m.AttributeRequests))
		for i, ib := range m.AttributeRequests {
			arr[i] = ib.Encode()
		}
		s[tlv.ContextTag(0)] = arr
	}
	if len(m.EventRequests) > 0 {
		arr := make([]tlv.List, len(m.EventRequests))
		for i, ib := range m.EventRequests {
			arr[i] = ib.Encode()
		}
		s[tlv.ContextTag(1)] = arr
	}
	if len(m.EventFilters) > 0 {
		arr := make(tlv.StructArray, 0, len(m.EventFilters))
		for _, ib := range m.EventFilters {
			arr = append(arr, ib.Encode())
		}
		s[tlv.ContextTag(2)] = arr
	}
	if len(m.DataVersionFilters) > 0 {
		arr := make(tlv.StructArray, 0, len(m.DataVersionFilters))
		for _, ib := range m.DataVersionFilters {
			arr = append(arr, ib.Encode())
		}
		s[tlv.ContextTag(4)] = arr
	}
	return s
}

func (m *ReadRequestMessage) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}

	if v, ok := st[tlv.ContextTag(0)]; ok {
		if arr, ok := v.([]tlv.List); ok {
			for _, child := range arr {
				var ib AttributePathIB
				ib.Decode(child)
				m.AttributeRequests = append(m.AttributeRequests, ib)
			}
		}
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		if arr, ok := v.([]tlv.List); ok {
			for _, child := range arr {
				var ib EventPathIB
				ib.Decode(child)
				m.EventRequests = append(m.EventRequests, ib)
			}
		}
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		if arr, ok := v.(tlv.StructArray); ok {
			for _, child := range arr {
				var ib EventFilterIB
				ib.Decode(child)
				m.EventFilters = append(m.EventFilters, ib)
			}
		}
	}
	if v, ok := st[tlv.ContextTag(3)]; ok {
		if b, ok := v.(bool); ok {
			m.FabricFiltered = b
		}
	}
	if v, ok := st[tlv.ContextTag(4)]; ok {
		if arr, ok := v.(tlv.StructArray); ok {
			for _, child := range arr {
				var ib DataVersionFilterIB
				ib.Decode(child)
				m.DataVersionFilters = append(m.DataVersionFilters, ib)
			}
		}
	}
	return nil
}

// SubscribeRequestMessage initiates a Subscribe interaction to establish a continuous reporting session for attribute and/or event data.
type SubscribeRequestMessage struct {
	// KeepSubscriptions indicates if existing subscriptions should be kept (Tag 0).
	KeepSubscriptions bool
	// MinIntervalFloor is the requested minimum interval (16 bits) (Tag 1).
	MinIntervalFloor uint16
	// MaxIntervalCeiling is the requested maximum interval (16 bits) (Tag 2).
	MaxIntervalCeiling uint16
	// AttributeRequests is a list of AttributePathIBs (Tag 3).
	AttributeRequests []AttributePathIB
	// EventRequests is a list of EventPathIBs (Tag 4).
	EventRequests []EventPathIB
	// EventFilters is a list of EventFilterIBs (Tag 5).
	EventFilters []EventFilterIB
	// FabricFiltered indicates whether to filter fabric-scoped lists to the accessing fabric (Tag 7).
	FabricFiltered bool
	// DataVersionFilters is a list of DataVersionFilterIBs (Tag 8).
	DataVersionFilters []DataVersionFilterIB
}

func (m *SubscribeRequestMessage) Encode() tlv.Struct {
	s := tlv.Struct{
		tlv.ContextTag(0): m.KeepSubscriptions,
		tlv.ContextTag(1): uint64(m.MinIntervalFloor),
		tlv.ContextTag(2): uint64(m.MaxIntervalCeiling),
		tlv.ContextTag(7): m.FabricFiltered,
	}
	if len(m.AttributeRequests) > 0 {
		arr := make([]tlv.List, len(m.AttributeRequests))
		for i, ib := range m.AttributeRequests {
			arr[i] = ib.Encode()
		}
		s[tlv.ContextTag(3)] = arr
	}
	if len(m.EventRequests) > 0 {
		arr := make([]tlv.List, len(m.EventRequests))
		for i, ib := range m.EventRequests {
			arr[i] = ib.Encode()
		}
		s[tlv.ContextTag(4)] = arr
	}
	if len(m.EventFilters) > 0 {
		arr := make(tlv.StructArray, 0, len(m.EventFilters))
		for _, ib := range m.EventFilters {
			arr = append(arr, ib.Encode())
		}
		s[tlv.ContextTag(5)] = arr
	}
	if len(m.DataVersionFilters) > 0 {
		arr := make(tlv.StructArray, 0, len(m.DataVersionFilters))
		for _, ib := range m.DataVersionFilters {
			arr = append(arr, ib.Encode())
		}
		s[tlv.ContextTag(8)] = arr
	}
	return s
}

func (m *SubscribeRequestMessage) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}

	if v, ok := st[tlv.ContextTag(0)]; ok {
		if b, ok := v.(bool); ok {
			m.KeepSubscriptions = b
		}
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		if u, ok := v.(uint64); ok {
			m.MinIntervalFloor = uint16(u)
		}
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		if u, ok := v.(uint64); ok {
			m.MaxIntervalCeiling = uint16(u)
		}
	}
	if v, ok := st[tlv.ContextTag(3)]; ok {
		if arr, ok := v.([]tlv.List); ok {
			for _, child := range arr {
				var ib AttributePathIB
				ib.Decode(child)
				m.AttributeRequests = append(m.AttributeRequests, ib)
			}
		}
	}
	if v, ok := st[tlv.ContextTag(4)]; ok {
		if arr, ok := v.([]tlv.List); ok {
			for _, child := range arr {
				var ib EventPathIB
				ib.Decode(child)
				m.EventRequests = append(m.EventRequests, ib)
			}
		}
	}
	if v, ok := st[tlv.ContextTag(5)]; ok {
		if arr, ok := v.(tlv.StructArray); ok {
			for _, child := range arr {
				var ib EventFilterIB
				ib.Decode(child)
				m.EventFilters = append(m.EventFilters, ib)
			}
		}
	}
	if v, ok := st[tlv.ContextTag(7)]; ok {
		if b, ok := v.(bool); ok {
			m.FabricFiltered = b
		}
	}
	if v, ok := st[tlv.ContextTag(8)]; ok {
		if arr, ok := v.(tlv.StructArray); ok {
			for _, child := range arr {
				var ib DataVersionFilterIB
				ib.Decode(child)
				m.DataVersionFilters = append(m.DataVersionFilters, ib)
			}
		}
	}
	return nil
}

// SubscribeResponseMessage is sent by the publisher to convey the final parameters and activate the subscription after all initial reports have been delivered.
type SubscribeResponseMessage struct {
	// SubscriptionID identifies the subscription (32 bits) (Tag 0).
	SubscriptionID uint32
	// MaxInterval is the finalized maximum reporting interval (16 bits) (Tag 2).
	MaxInterval uint16
}

func (m *SubscribeResponseMessage) Encode() tlv.Struct {
	return tlv.Struct{
		tlv.ContextTag(0): uint64(m.SubscriptionID),
		tlv.ContextTag(2): uint64(m.MaxInterval),
	}
}

func (m *SubscribeResponseMessage) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		m.SubscriptionID = uint32(v.(uint64))
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		m.MaxInterval = uint16(v.(uint64))
	}
	return nil
}

// ReportDataMessage is sent to fulfill a Read Request or to send primed/periodic data for a Subscribe interaction.
type ReportDataMessage struct {
	// SubscriptionID identifies the subscription (32 bits). Present if part of a subscription (Tag 0).
	SubscriptionID *uint32
	// AttributeReports is a list of AttributeReportIBs (Tag 1).
	AttributeReports []AttributeReportIB
	// EventReports is a list of EventReportIBs (Tag 2).
	EventReports []EventReportIB
	// MoreChunkedMessages indicates if the payload exceeds the MTU and more blocks are coming (Tag 3).
	MoreChunkedMessages bool
	// SuppressResponse indicates whether a response is suppressed (Tag 4).
	SuppressResponse bool
}

func (m *ReportDataMessage) Encode() tlv.Struct {
	s := tlv.Struct{}
	if m.SubscriptionID != nil {
		s[tlv.ContextTag(0)] = uint64(*m.SubscriptionID)
	}
	if len(m.AttributeReports) > 0 {
		arr := make(tlv.StructArray, 0, len(m.AttributeReports))
		for _, ib := range m.AttributeReports {
			arr = append(arr, ib.Encode())
		}
		s[tlv.ContextTag(1)] = arr
	}
	if len(m.EventReports) > 0 {
		arr := make(tlv.StructArray, 0, len(m.EventReports))
		for _, ib := range m.EventReports {
			arr = append(arr, ib.Encode())
		}
		s[tlv.ContextTag(2)] = arr
	}
	if m.MoreChunkedMessages {
		s[tlv.ContextTag(3)] = m.MoreChunkedMessages
	}
	if m.SuppressResponse {
		s[tlv.ContextTag(4)] = m.SuppressResponse
	}
	return s
}

func (m *ReportDataMessage) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}

	if v, ok := st[tlv.ContextTag(0)]; ok {
		id := uint32(v.(uint64))
		m.SubscriptionID = &id
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		if arr, ok := v.(tlv.StructArray); ok {
			for _, child := range arr {
				var ib AttributeReportIB
				ib.Decode(child)
				m.AttributeReports = append(m.AttributeReports, ib)
			}
		}
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		if arr, ok := v.(tlv.StructArray); ok {
			for _, child := range arr {
				var ib EventReportIB
				ib.Decode(child)
				m.EventReports = append(m.EventReports, ib)
			}
		}
	}
	if v, ok := st[tlv.ContextTag(3)]; ok {
		m.MoreChunkedMessages = v.(bool)
	}
	if v, ok := st[tlv.ContextTag(4)]; ok {
		m.SuppressResponse = v.(bool)
	}
	return nil
}

// WriteRequestMessage initiates a Write transaction to modify attribute data.
type WriteRequestMessage struct {
	// SuppressResponse indicates whether a response is suppressed (Tag 0).
	SuppressResponse bool
	// TimedRequest indicates if this is part of a timed interaction (Tag 1).
	TimedRequest bool
	// WriteRequests is a list of AttributeDataIBs containing the paths and new values (Tag 2).
	WriteRequests []AttributeDataIB
	// MoreChunkedMessages indicates if the write payload spans multiple messages (Tag 3).
	MoreChunkedMessages bool
}

func (m *WriteRequestMessage) Encode() tlv.Struct {
	s := tlv.Struct{}
	if m.SuppressResponse {
		s[tlv.ContextTag(0)] = m.SuppressResponse
	}
	if m.TimedRequest {
		s[tlv.ContextTag(1)] = m.TimedRequest
	}
	if len(m.WriteRequests) > 0 {
		arr := make(tlv.StructArray, 0, len(m.WriteRequests))
		for _, ib := range m.WriteRequests {
			arr = append(arr, ib.Encode())
		}
		s[tlv.ContextTag(2)] = arr
	}
	if m.MoreChunkedMessages {
		s[tlv.ContextTag(3)] = m.MoreChunkedMessages
	}
	return s
}

func (m *WriteRequestMessage) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}

	if v, ok := st[tlv.ContextTag(0)]; ok {
		m.SuppressResponse = v.(bool)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		m.TimedRequest = v.(bool)
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		if arr, ok := v.(tlv.StructArray); ok {
			for _, child := range arr {
				var ib AttributeDataIB
				ib.Decode(child)
				m.WriteRequests = append(m.WriteRequests, ib)
			}
		}
	}
	if v, ok := st[tlv.ContextTag(3)]; ok {
		m.MoreChunkedMessages = v.(bool)
	}
	return nil
}

// WriteResponseMessage is sent in response to a Write Request to indicate success or error for each requested path.
type WriteResponseMessage struct {
	// WriteResponses is a list of AttributeStatusIBs containing the status for each write path (Tag 0).
	WriteResponses []AttributeStatusIB
}

func (m *WriteResponseMessage) Encode() tlv.Struct {
	s := tlv.Struct{}
	if len(m.WriteResponses) > 0 {
		arr := make(tlv.StructArray, 0, len(m.WriteResponses))
		for _, ib := range m.WriteResponses {
			arr = append(arr, ib.Encode())
		}
		s[tlv.ContextTag(0)] = arr
	}
	return s
}

func (m *WriteResponseMessage) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		if arr, ok := v.(tlv.StructArray); ok {
			for _, child := range arr {
				var ib AttributeStatusIB
				ib.Decode(child)
				m.WriteResponses = append(m.WriteResponses, ib)
			}
		}
	}
	return nil
}

// InvokeRequestMessage initiates an Invoke transaction to execute one or more cluster commands.
type InvokeRequestMessage struct {
	// SuppressResponse indicates whether a response is suppressed (Tag 0).
	SuppressResponse bool
	// TimedRequest indicates if this is part of a timed interaction (Tag 1).
	TimedRequest bool
	// InvokeRequests is a list of CommandDataIBs containing the command paths and arguments (Tag 2).
	InvokeRequests []CommandDataIB
}

func (m *InvokeRequestMessage) Encode() tlv.Struct {
	s := tlv.Struct{}
	if m.SuppressResponse {
		s[tlv.ContextTag(0)] = m.SuppressResponse
	}
	if m.TimedRequest {
		s[tlv.ContextTag(1)] = m.TimedRequest
	}
	if len(m.InvokeRequests) > 0 {
		arr := make(tlv.StructArray, 0, len(m.InvokeRequests))
		for _, ib := range m.InvokeRequests {
			arr = append(arr, ib.Encode())
		}
		s[tlv.ContextTag(2)] = arr
	}
	return s
}

func (m *InvokeRequestMessage) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}

	if v, ok := st[tlv.ContextTag(0)]; ok {
		m.SuppressResponse = v.(bool)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		m.TimedRequest = v.(bool)
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		if arr, ok := v.(tlv.StructArray); ok {
			for _, child := range arr {
				var ib CommandDataIB
				ib.Decode(child)
				m.InvokeRequests = append(m.InvokeRequests, ib)
			}
		}
	}
	return nil
}

// InvokeResponseMessage is sent in response to an Invoke Request to provide command execution status or return data.
type InvokeResponseMessage struct {
	// SuppressResponse indicates whether a response is suppressed (Tag 0).
	SuppressResponse bool
	// InvokeResponses is a list of InvokeResponseIBs containing the returned data or status for each invoked command (Tag 1).
	InvokeResponses []InvokeResponseIB
	// MoreChunkedMessages indicates if the payload exceeds the MTU and more blocks are coming (Tag 2).
	MoreChunkedMessages bool
}

func (m *InvokeResponseMessage) Encode() tlv.Struct {
	s := tlv.Struct{}
	if m.SuppressResponse {
		s[tlv.ContextTag(0)] = m.SuppressResponse
	}
	if len(m.InvokeResponses) > 0 {
		arr := make(tlv.StructArray, 0, len(m.InvokeResponses))
		for _, ib := range m.InvokeResponses {
			arr = append(arr, ib.Encode())
		}
		s[tlv.ContextTag(1)] = arr
	}
	if m.MoreChunkedMessages {
		s[tlv.ContextTag(2)] = m.MoreChunkedMessages
	}
	return s
}

func (m *InvokeResponseMessage) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}

	if v, ok := st[tlv.ContextTag(0)]; ok {
		m.SuppressResponse = v.(bool)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		if arr, ok := v.(tlv.StructArray); ok {
			for _, child := range arr {
				var ib InvokeResponseIB
				ib.Decode(child)
				m.InvokeResponses = append(m.InvokeResponses, ib)
			}
		}
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		m.MoreChunkedMessages = v.(bool)
	}
	return nil
}

// TimedRequestMessage is sent as a precursor to a Write Request or Invoke Request to establish a timed window (preventing intercept-and-replay attacks).
type TimedRequestMessage struct {
	// Timeout defines the time interval in milliseconds within which the subsequent message must arrive (16 bits) (Tag 0).
	Timeout uint16
}

func (m *TimedRequestMessage) Encode() tlv.Struct {
	return tlv.Struct{
		tlv.ContextTag(0): uint64(m.Timeout),
	}
}

func (m *TimedRequestMessage) Decode(data []byte) error {
	val, err := tlv.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		m.Timeout = uint16(v.(uint64))
	}
	return nil
}

// IB structs

// ClusterPathIB identifies a specific cluster instance on a node.
type ClusterPathIB struct {
	// Node is the target Node ID (64-bit) (Tag 0).
	Node *uint64
	// Endpoint is the target Endpoint (16-bit) (Tag 1).
	Endpoint *uint16
	// Cluster is the target Cluster ID (32-bit) (Tag 2).
	Cluster *uint32
}

func (ib *ClusterPathIB) Encode() tlv.List {
	var l tlv.List
	if ib.Node != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(0), Value: *ib.Node})
	}
	if ib.Endpoint != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(1), Value: uint64(*ib.Endpoint)})
	}
	if ib.Cluster != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(2), Value: uint64(*ib.Cluster)})
	}
	return l
}

func (ib *ClusterPathIB) Decode(val any) error {
	list, ok := val.(tlv.List)
	if !ok {
		return fmt.Errorf("expected list, got %T", val)
	}
	for _, elem := range list {
		switch elem.Tag {
		case tlv.ContextTag(0):
			v := elem.Value.(uint64)
			ib.Node = &v
		case tlv.ContextTag(1):
			v := uint16(elem.Value.(uint64))
			ib.Endpoint = &v
		case tlv.ContextTag(2):
			v := uint32(elem.Value.(uint64))
			ib.Cluster = &v
		}
	}
	return nil
}

// AttributePathIB identifies an attribute or a specific deeper nested element (like a list entry).
type AttributePathIB struct {
	// EnableTagCompression, if true, indicates omitted tags inherit from the previous path in the message (Tag 0).
	EnableTagCompression *bool
	// Node is the target Node ID (64-bit) (Tag 1).
	Node *uint64
	// Endpoint is the target Endpoint (16-bit) (Tag 2).
	Endpoint *uint16
	// Cluster is the target Cluster ID (32-bit) (Tag 3).
	Cluster *uint32
	// Attribute is the target Attribute ID (32-bit) (Tag 4).
	Attribute *uint32
	// ListIndex is used to address a specific entry in a list attribute (16-bit, nullable) (Tag 5).
	ListIndex *uint16
	// WildcardPathFlags is used to explicitly skip certain elements during wildcard expansion (32-bit) (Tag 6).
	WildcardPathFlags *uint32
}

func (ib *AttributePathIB) Encode() tlv.List {
	var l tlv.List
	if ib.EnableTagCompression != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(0), Value: *ib.EnableTagCompression})
	}
	if ib.Node != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(1), Value: *ib.Node})
	}
	if ib.Endpoint != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(2), Value: uint64(*ib.Endpoint)})
	}
	if ib.Cluster != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(3), Value: uint64(*ib.Cluster)})
	}
	if ib.Attribute != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(4), Value: uint64(*ib.Attribute)})
	}
	if ib.ListIndex != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(5), Value: uint64(*ib.ListIndex)})
	}
	if ib.WildcardPathFlags != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(6), Value: uint64(*ib.WildcardPathFlags)})
	}
	return l
}

func (ib *AttributePathIB) Decode(val any) error {
	list, ok := val.(tlv.List)
	if !ok {
		return fmt.Errorf("expected list, got %T", val)
	}
	for _, elem := range list {
		switch elem.Tag {
		case tlv.ContextTag(0):
			v := elem.Value.(bool)
			ib.EnableTagCompression = &v
		case tlv.ContextTag(1):
			v := elem.Value.(uint64)
			ib.Node = &v
		case tlv.ContextTag(2):
			v := uint16(elem.Value.(uint64))
			ib.Endpoint = &v
		case tlv.ContextTag(3):
			v := uint32(elem.Value.(uint64))
			ib.Cluster = &v
		case tlv.ContextTag(4):
			v := uint32(elem.Value.(uint64))
			ib.Attribute = &v
		case tlv.ContextTag(5):
			v := uint16(elem.Value.(uint64))
			ib.ListIndex = &v
		case tlv.ContextTag(6):
			v := uint32(elem.Value.(uint64))
			ib.WildcardPathFlags = &v
		}
	}
	return nil
}

// EventPathIB identifies an event type.
type EventPathIB struct {
	// Node is the target Node ID (64-bit) (Tag 0).
	Node *uint64
	// Endpoint is the target Endpoint (16-bit) (Tag 1).
	Endpoint *uint16
	// Cluster is the target Cluster ID (32-bit) (Tag 2).
	Cluster *uint32
	// Event is the target Event ID (32-bit) (Tag 3).
	Event *uint32
	// IsUrgent indicates that this event should immediately trigger a report rather than waiting in the queue (Tag 4).
	IsUrgent *bool
}

func (ib *EventPathIB) Encode() tlv.List {
	var l tlv.List
	if ib.Node != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(0), Value: *ib.Node})
	}
	if ib.Endpoint != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(1), Value: uint64(*ib.Endpoint)})
	}
	if ib.Cluster != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(2), Value: uint64(*ib.Cluster)})
	}
	if ib.Event != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(3), Value: uint64(*ib.Event)})
	}
	if ib.IsUrgent != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(4), Value: *ib.IsUrgent})
	}
	return l
}

func (ib *EventPathIB) Decode(val any) error {
	list, ok := val.(tlv.List)
	if !ok {
		return fmt.Errorf("expected list, got %T", val)
	}
	for _, elem := range list {
		switch elem.Tag {
		case tlv.ContextTag(0):
			v := elem.Value.(uint64)
			ib.Node = &v
		case tlv.ContextTag(1):
			v := uint16(elem.Value.(uint64))
			ib.Endpoint = &v
		case tlv.ContextTag(2):
			v := uint32(elem.Value.(uint64))
			ib.Cluster = &v
		case tlv.ContextTag(3):
			v := uint32(elem.Value.(uint64))
			ib.Event = &v
		case tlv.ContextTag(4):
			v := elem.Value.(bool)
			ib.IsUrgent = &v
		}
	}
	return nil
}

// EventFilterIB is used by clients to request only events that occurred after a specific event number.
type EventFilterIB struct {
	// Node is the target Node ID (64-bit) (Tag 0).
	Node *uint64
	// EventMin is the minimum event number to report (64-bit) (Tag 1).
	EventMin uint64
}

func (ib *EventFilterIB) Encode() tlv.Struct {
	s := tlv.Struct{
		tlv.ContextTag(1): ib.EventMin,
	}
	if ib.Node != nil {
		s[tlv.ContextTag(0)] = *ib.Node
	}
	return s
}

func (ib *EventFilterIB) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		u := v.(uint64)
		ib.Node = &u
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		ib.EventMin = v.(uint64)
	}
	return nil
}

// DataVersionFilterIB is used by clients in a Read/Subscribe Request to skip reporting if the server's data version matches this filter.
type DataVersionFilterIB struct {
	// Path identifies the cluster instance (Tag 0).
	Path ClusterPathIB
	// DataVersion is the cluster's data version (32-bit) (Tag 1).
	DataVersion uint32
}

func (ib *DataVersionFilterIB) Encode() tlv.Struct {
	return tlv.Struct{
		tlv.ContextTag(0): ib.Path.Encode(),
		tlv.ContextTag(1): uint64(ib.DataVersion),
	}
}

func (ib *DataVersionFilterIB) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		ib.Path.Decode(v)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		ib.DataVersion = uint32(v.(uint64))
	}
	return nil
}

// AttributeDataIB packages the actual payload for a write or report action.
type AttributeDataIB struct {
	// DataVersion is the cluster's data version (32-bit) (Tag 0).
	DataVersion *uint32
	// Path identifies the attribute (Tag 1).
	Path AttributePathIB
	// Data is the actual data dictated by the Data Model schema (Tag 2).
	Data any
}

func (ib *AttributeDataIB) Encode() tlv.Struct {
	s := tlv.Struct{
		tlv.ContextTag(1): ib.Path.Encode(),
	}
	if ib.DataVersion != nil {
		s[tlv.ContextTag(0)] = uint64(*ib.DataVersion)
	}
	if ib.Data != nil {
		s[tlv.ContextTag(2)] = ib.Data
	}
	return s
}

func (ib *AttributeDataIB) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		u := uint32(v.(uint64))
		ib.DataVersion = &u
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		ib.Path.Decode(v)
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		ib.Data = v
	}
	return nil
}

// StatusIB conveys errors or success across the entire Interaction Model.
type StatusIB struct {
	// Status is the global Interaction Model Status Code (8-bit) (Tag 0).
	Status *uint8
	// ClusterStatus is a cluster-specific status code (8-bit) (Tag 1).
	ClusterStatus *uint8
}

func (ib *StatusIB) Encode() tlv.Struct {
	s := tlv.Struct{}
	if ib.Status != nil {
		s[tlv.ContextTag(0)] = uint64(*ib.Status)
	}
	if ib.ClusterStatus != nil {
		s[tlv.ContextTag(1)] = uint64(*ib.ClusterStatus)
	}
	return s
}

func (ib *StatusIB) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		u := uint8(v.(uint64))
		ib.Status = &u
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		u := uint8(v.(uint64))
		ib.ClusterStatus = &u
	}
	return nil
}

// AttributeStatusIB conveys the success or error status of an operation on a specific attribute.
type AttributeStatusIB struct {
	// Path identifies the attribute (Tag 0).
	Path AttributePathIB
	// Status is the result of the operation (Tag 1).
	Status StatusIB
}

func (ib *AttributeStatusIB) Encode() tlv.Struct {
	return tlv.Struct{
		tlv.ContextTag(0): ib.Path.Encode(),
		tlv.ContextTag(1): ib.Status.Encode(),
	}
}

func (ib *AttributeStatusIB) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		ib.Path.Decode(v)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		ib.Status.Decode(v)
	}
	return nil
}

// AttributeReportIB is a wrapper used in ReportDataMessage. Only one of the two fields will be present.
type AttributeReportIB struct {
	// AttributeStatus contains the error status (Tag 0).
	AttributeStatus *AttributeStatusIB
	// AttributeData contains the data payload (Tag 1).
	AttributeData *AttributeDataIB
}

func (ib *AttributeReportIB) Encode() tlv.Struct {
	s := tlv.Struct{}
	if ib.AttributeStatus != nil {
		s[tlv.ContextTag(0)] = ib.AttributeStatus.Encode()
	} else if ib.AttributeData != nil {
		s[tlv.ContextTag(1)] = ib.AttributeData.Encode()
	}
	return s
}

func (ib *AttributeReportIB) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		ib.AttributeStatus = &AttributeStatusIB{}
		ib.AttributeStatus.Decode(v)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		ib.AttributeData = &AttributeDataIB{}
		ib.AttributeData.Decode(v)
	}
	return nil
}

// EventStatusIB conveys the error status when attempting to interact with an event.
type EventStatusIB struct {
	// Path identifies the event (Tag 0).
	Path EventPathIB
	// Status is the result of the operation (Tag 1).
	Status StatusIB
}

func (ib *EventStatusIB) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		ib.Path.Decode(v)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		ib.Status.Decode(v)
	}
	return nil
}

// EventDataIB packages a single historical event record.
type EventDataIB struct {
	// Path identifies the event (Tag 0).
	Path EventPathIB
	// EventNumber is the unique event identifier (64-bit) (Tag 1).
	EventNumber uint64
	// Priority is the priority of the event (Debug, Info, Critical) (8-bit) (Tag 2).
	Priority uint8
	// Data is the actual event payload (Tag 5).
	Data any
}

func (ib *EventDataIB) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		ib.Path.Decode(v)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		ib.EventNumber = v.(uint64)
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		ib.Priority = uint8(v.(uint64))
	}
	if v, ok := st[tlv.ContextTag(7)]; ok {
		ib.Data = v
	}
	return nil
}

// EventReportIB is a wrapper used in ReportDataMessage. Only one of the two fields will be present.
type EventReportIB struct {
	// EventStatus contains the error status (Tag 0).
	EventStatus *EventStatusIB
	// EventData contains the event payload (Tag 1).
	EventData *EventDataIB
}

func (ib *EventReportIB) Encode() tlv.Struct {
	s := tlv.Struct{}
	if ib.EventStatus != nil {
		s[tlv.ContextTag(0)] = ib.EventStatus.Encode()
	} else if ib.EventData != nil {
		s[tlv.ContextTag(1)] = ib.EventData.Encode()
	}
	return s
}

func (ib *EventReportIB) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		ib.EventStatus = &EventStatusIB{}
		ib.EventStatus.Decode(v)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		ib.EventData = &EventDataIB{}
		ib.EventData.Decode(v)
	}
	return nil
}

func (ib *EventStatusIB) Encode() tlv.Struct {
	return tlv.Struct{
		tlv.ContextTag(0): ib.Path.Encode(),
		tlv.ContextTag(1): ib.Status.Encode(),
	}
}

func (ib *EventDataIB) Encode() tlv.Struct {
	s := tlv.Struct{
		tlv.ContextTag(0): ib.Path.Encode(),
		tlv.ContextTag(1): ib.EventNumber,
		tlv.ContextTag(2): uint64(ib.Priority),
	}
	if ib.Data != nil {
		s[tlv.ContextTag(7)] = ib.Data
	}
	return s
}

// CommandPathIB identifies a cluster command.
type CommandPathIB struct {
	// EndpointId is the target Endpoint (16-bit) (Tag 0).
	EndpointId *uint16
	// ClusterId is the target Cluster ID (32-bit) (Tag 1).
	ClusterId *uint32
	// CommandId is the Command ID (32-bit) (Tag 2).
	CommandId *uint32
}

func (ib *CommandPathIB) Encode() tlv.List {
	var l tlv.List
	if ib.EndpointId != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(0), Value: uint64(*ib.EndpointId)})
	}
	if ib.ClusterId != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(1), Value: uint64(*ib.ClusterId)})
	}
	if ib.CommandId != nil {
		l = append(l, tlv.Element{Tag: tlv.ContextTag(2), Value: uint64(*ib.CommandId)})
	}
	return l
}

func (ib *CommandPathIB) Decode(val any) error {
	list, ok := val.(tlv.List)
	if !ok {
		return fmt.Errorf("expected list, got %T", val)
	}
	for _, elem := range list {
		switch elem.Tag {
		case tlv.ContextTag(0):
			v := uint16(elem.Value.(uint64))
			ib.EndpointId = &v
		case tlv.ContextTag(1):
			v := uint32(elem.Value.(uint64))
			ib.ClusterId = &v
		case tlv.ContextTag(2):
			v := uint32(elem.Value.(uint64))
			ib.CommandId = &v
		}
	}
	return nil
}

// CommandDataIB contains the command path and the arguments to execute it.
type CommandDataIB struct {
	// Path identifies the command (Tag 0).
	Path CommandPathIB
	// Fields contains the command arguments (Tag 1).
	Fields any
}

func (ib *CommandDataIB) Encode() tlv.Struct {
	s := tlv.Struct{
		tlv.ContextTag(0): ib.Path.Encode(),
	}
	if ib.Fields != nil {
		s[tlv.ContextTag(1)] = ib.Fields
	}
	return s
}

func (ib *CommandDataIB) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		ib.Path.Decode(v)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		ib.Fields = v
	}
	return nil
}

// CommandStatusIB conveys a success or error status as a response to an invoked command.
type CommandStatusIB struct {
	// Path identifies the command (Tag 0).
	Path CommandPathIB
	// Status is the result of the execution (Tag 1).
	Status StatusIB
}

func (ib *CommandStatusIB) Encode() tlv.Struct {
	return tlv.Struct{
		tlv.ContextTag(0): ib.Path.Encode(),
		tlv.ContextTag(1): ib.Status.Encode(),
	}
}

func (ib *CommandStatusIB) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		ib.Path.Decode(v)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		ib.Status.Decode(v)
	}
	return nil
}

// InvokeResponseIB is a wrapper used in InvokeResponseMessage. Only one of the two fields will be present.
type InvokeResponseIB struct {
	// Command contains the returned data (Tag 0).
	Command *CommandDataIB
	// Status contains the execution status (Tag 1).
	Status *CommandStatusIB
}

func (ib *InvokeResponseIB) Encode() tlv.Struct {
	s := tlv.Struct{}
	if ib.Command != nil {
		s[tlv.ContextTag(0)] = ib.Command.Encode()
	} else if ib.Status != nil {
		s[tlv.ContextTag(1)] = ib.Status.Encode()
	}
	return s
}

func (ib *InvokeResponseIB) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		ib.Command = &CommandDataIB{}
		ib.Command.Decode(v)
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		ib.Status = &CommandStatusIB{}
		ib.Status.Decode(v)
	}
	return nil
}

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

Based on the Matter Interaction Model Encoding Specification, the `*IB` structures stand for **Information Blocks**. They are the reusable components encapsulated within the top-level Interaction Model messages (like `ReadRequestMessage` or `ReportDataMessage`) to convey paths, data, and statuses.

Here is the detailed specification of all the core Information Blocks used in the Interaction Model, organized by their functional category:

### 11. Path Information Blocks
These IBs define the routing coordinates (Paths) to specific Data Model elements. To optimize encoding size, these are typically encoded as **TLV Lists** (rather than Structures), allowing wildcarding by simply omitting tags.

*   **`ClusterPathIB`** (TLV Type: List)
    Identifies a specific cluster instance on a node.
    *   `Node` (Tag 0): Unsigned Integer (64-bit). Target Node ID.
    *   `Endpoint` (Tag 1): Unsigned Integer (16-bit). Target Endpoint.
    *   `Cluster` (Tag 2): Unsigned Integer (32-bit). Target Cluster ID.
*   **`AttributePathIB`** (TLV Type: List)
    Identifies an attribute or a specific deeper nested element (like a list entry).
    *   `EnableTagCompression` (Tag 0): Boolean. If true, omitted tags inherit from the previous path in the message.
    *   `Node` (Tag 1): Unsigned Integer (64-bit).
    *   `Endpoint` (Tag 2): Unsigned Integer (16-bit).
    *   `Cluster` (Tag 3): Unsigned Integer (32-bit).
    *   `Attribute` (Tag 4): Unsigned Integer (32-bit). Attribute ID.
    *   `ListIndex` (Tag 5): Unsigned Integer (16-bit, nullable). Used to address a specific entry in a list attribute.
    *   `WildcardPathFlags` (Tag 6): Unsigned Integer (32-bit). Used to explicitly skip certain elements during wildcard expansion (e.g., skip global attributes or diagnostics clusters).
*   **`EventPathIB`** (TLV Type: List)
    Identifies an event type.
    *   `Node` (Tag 0): Unsigned Integer (64-bit).
    *   `Endpoint` (Tag 1): Unsigned Integer (16-bit).
    *   `Cluster` (Tag 2): Unsigned Integer (32-bit).
    *   `Event` (Tag 3): Unsigned Integer (32-bit). Event ID.
    *   `IsUrgent` (Tag 4): Boolean. Used in subscriptions to indicate that this event should immediately trigger a report rather than waiting in the queue.
*   **`CommandPathIB`** (TLV Type: List)
    Identifies a cluster command.
    *   `Endpoint` (Tag 0): Unsigned Integer (16-bit).
    *   `Cluster` (Tag 1): Unsigned Integer (32-bit).
    *   `Command` (Tag 2): Unsigned Integer (32-bit). Command ID.

### 12. Attribute Information Blocks
These IBs package the actual payload and statuses for attributes. They are encoded as **TLV Structures**.

*   **`AttributeDataIB`** (TLV Type: Structure)
    Packages the actual payload for a write or report action.
    *   `DataVersion` (Tag 0): Unsigned Integer (32-bit). The cluster's data version.
    *   `Path` (Tag 1): `AttributePathIB`.
    *   `Data` (Tag 2): Variable TLV element. The actual data dictated by the Data Model schema.
*   **`DataVersionFilterIB`** (TLV Type: Structure)
    Used by clients in a Read/Subscribe Request to skip reporting if the server's data version matches this filter (optimizes bandwidth).
    *   `Path` (Tag 0): `ClusterPathIB`.
    *   `DataVersion` (Tag 1): Unsigned Integer (32-bit).
*   **`AttributeStatusIB`** (TLV Type: Structure)
    Conveys the success or error status of an operation on a specific attribute.
    *   `Path` (Tag 0): `AttributePathIB`.
    *   `Status` (Tag 1): `StatusIB`.
*   **`AttributeReportIB`** (TLV Type: Anonymous Structure)
    A wrapper used in `ReportDataMessage`. **Only one** of the two fields will be present, depending on whether the report is returning data or an error.
    *   `AttributeStatus` (Tag 0): `AttributeStatusIB`.
    *   `AttributeData` (Tag 1): `AttributeDataIB`.

### 13. Event Information Blocks
These IBs package the payloads, filters, and statuses for events.

*   **`EventFilterIB`** (TLV Type: Anonymous Structure)
    Used by clients to request only events that occurred after a specific event number.
    *   `Node` (Tag 0): Unsigned Integer (64-bit).
    *   `EventMin` (Tag 1): Unsigned Integer (64-bit). The minimum event number to report.
*   **`EventDataIB`** (TLV Type: Structure)
    Packages a single historical event record.
    *   `Path` (Tag 0): `EventPathIB`.
    *   `EventNumber` (Tag 1): Unsigned Integer (64-bit).
    *   `Priority` (Tag 2): Unsigned Integer (8-bit). Priority of the event (Debug, Info, Critical).
    *   `EpochTimeStamp` (Tag 3): Unsigned Integer. Time since epoch.
    *   `SystemTimeStamp` (Tag 4): Unsigned Integer. Time since boot.
    *   `Data` (Tag 5): Variable TLV element. The actual event payload.
*   **`EventStatusIB`** (TLV Type: Structure)
    Conveys the error status when attempting to interact with an event.
    *   `Path` (Tag 0): `EventPathIB`.
    *   `Status` (Tag 1): `StatusIB`.
*   **`EventReportIB`** (TLV Type: Anonymous Structure)
    A wrapper used in `ReportDataMessage`. **Only one** of the two fields will be present.
    *   `EventStatus` (Tag 0): `EventStatusIB`.
    *   `EventData` (Tag 1): `EventDataIB`.

### 14. Command Information Blocks
These IBs are used in Invoke requests and responses to package the command arguments and execution results.

*   **`CommandDataIB`** (TLV Type: Anonymous Structure)
    Contains the command path and the arguments (fields) to execute it.
    *   `CommandPath` (Tag 0): `CommandPathIB`.
    *   `CommandFields` (Tag 1, Optional): Variable TLV element. The struct containing the command arguments.
    *   `CommandRef` (Tag 2, Optional): Unsigned Integer (16-bit). Used to uniquely identify the command in a batch of multiple commands, so the response can be accurately correlated.
*   **`CommandStatusIB`** (TLV Type: Structure)
    Conveys a success or error status as a response to an invoked command.
    *   `CommandPath` (Tag 0): `CommandPathIB`.
    *   `Status` (Tag 1): `StatusIB`.
    *   `CommandRef` (Tag 2, Optional): Unsigned Integer (16-bit). Matches the `CommandRef` of the request.
*   **`InvokeResponseIB`** (TLV Type: Anonymous Structure)
    A wrapper used in `InvokeResponseMessage`. **Only one** of the two fields will be present. If the command returns data, `Command` is used. If it just returns a success/failure code, `Status` is used.
    *   `Command` (Tag 0): `CommandDataIB`.
    *   `Status` (Tag 1): `CommandStatusIB`.

### 15. Core Status Block
*   **`StatusIB`** (TLV Type: Structure)
    The most foundational building block for conveying errors or success across the entire Interaction Model.
    *   `Status` (Tag 0): Unsigned Integer (8-bit). The global Interaction Model Status Code (e.g., 0x00 for SUCCESS, 0x01 for FAILURE, 0x86 for UNSUPPORTED_ACCESS).
    *   `ClusterStatus` (Tag 1, Optional): Unsigned Integer (8-bit). A cluster-specific status code that provides more granular error information defined by the target cluster's specification.

*/
