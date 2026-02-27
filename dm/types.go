package dm

import (
	"fmt"

	"github.com/etnz/matter/tlv"
)

// SubjectID identifies who or what is requesting an action in Access Control.
// It is always a 64-bit unsigned integer, but its meaning changes depending on the AuthMode:
// - CASE: Node ID (64-bit) or CASE Authenticated Tag (32-bit).
// - Group: Group ID (lower 16 bits).
// - PASE: Passcode ID (lower 16 bits).
type SubjectID uint64

// NodeID is an 8-byte/64-bit identifier for a node, scoped to a particular fabric.
type NodeID uint64

// FabricID is an 8-byte/64-bit identifier for a fabric.
type FabricID uint64

// EventNumber is an 8-byte/64-bit monotonically increasing event number.
type EventNumber uint64

// ClusterID is a 4-byte/32-bit identifier indicating conformance to a cluster specification.
type ClusterID uint32

// AttributeID is a 4-byte/32-bit identifier for an attribute.
type AttributeID uint32

// CommandID is a 4-byte/32-bit identifier for a command.
type CommandID uint32

// EventID is a 4-byte/32-bit identifier for an event.
type EventID uint32

// DeviceTypeID is a 4-byte/32-bit identifier for a device type.
type DeviceTypeID uint32

// DataVersion is a 4-byte/32-bit data version counter.
type DataVersion uint32

// EndpointID is a 2-byte/16-bit number indicating an instance of a device type.
type EndpointID uint16

// GroupID is a 2-byte/16-bit identifier for a group scoped to a fabric.
type GroupID uint16

// VendorID is a 2-byte/16-bit Vendor ID.
type VendorID uint16

// EntryIndex is a 2-byte/16-bit index used for list data types.
type EntryIndex uint16

// FabricIndex is a 1-byte/8-bit local index that maps to a specific fabric on the node.
type FabricIndex uint8

// ActionID is a 1-byte/8-bit Interaction Model action identifier.
type ActionID uint8

// EpochS is a time in seconds since the Matter Epoch (2000-01-01 00:00:00 UTC).
type EpochS uint32

// EpochUS is a time in microseconds since the Matter Epoch.
type EpochUS uint64

// SystemTimeMS is a system time in milliseconds (since boot).
type SystemTimeMS uint64

// ElapsedS is a duration in seconds.
type ElapsedS uint32

// PowerMW is power in milliwatts.
type PowerMW int64

// EnergyMWh is energy in milliwatt-hours.
type EnergyMWh int64

// Temperature is temperature in 0.01 degrees Celsius.
type Temperature int16

// Percent is a percentage (0-100).
type Percent uint8

// Percent100ths is a percentage in 0.01% steps (0-10000).
type Percent100ths uint16

// HardwareAddress is a hardware address (e.g. MAC address), typically 6 or 8 bytes.
type HardwareAddress []byte

// PosixMS is POSIX Time in milliseconds.
type PosixMS uint64

// SystemTimeUS is System Time in microseconds.
type SystemTimeUS uint64

// UTC is UTC Time (Deprecated, same as EpochS).
type UTC uint32

// AmperageMA is Amperage in milliamps.
type AmperageMA int64

// VoltageMW is Voltage in millivolts.
type VoltageMW int64

// FieldID is a Struct Field Identifier.
type FieldID uint32

// TransactionID is a Transaction ID.
type TransactionID uint32

// Enum8 is an 8-bit Enumeration.
type Enum8 uint8

// Enum16 is a 16-bit Enumeration.
type Enum16 uint16

// Status is a Status Code.
type Status uint8

// Priority is a Priority level.
type Priority uint8

// IPAddress is an IP Address (4 or 16 bytes).
type IPAddress []byte

// IPv4Address is an IPv4 Address (4 bytes).
type IPv4Address []byte

// IPv6Address is an IPv6 Address (16 bytes).
type IPv6Address []byte

// IPv6Prefix is an IPv6 Prefix.
type IPv6Prefix []byte

// Namespace for a semantic tag.
type Namespace uint8

// Tag within a namespace.
type Tag uint8

type MessageID []byte

// MeasurementTypeEnum identifies the type of electrical measurement.
type MeasurementTypeEnum uint16

const (
	// MeasurementTypeEnumUnspecified is an unspecified measurement type.
	MeasurementTypeEnumUnspecified MeasurementTypeEnum = 0
	// MeasurementTypeEnumVoltage is Voltage in mV.
	MeasurementTypeEnumVoltage MeasurementTypeEnum = 1
	// MeasurementTypeEnumActiveCurrent is ActiveCurrent in mA.
	MeasurementTypeEnumActiveCurrent MeasurementTypeEnum = 2
	// MeasurementTypeEnumReactiveCurrent is ReactiveCurrent in mA.
	MeasurementTypeEnumReactiveCurrent MeasurementTypeEnum = 3
	// MeasurementTypeEnumApparentCurrent is ApparentCurrent in mA.
	MeasurementTypeEnumApparentCurrent MeasurementTypeEnum = 4
	// MeasurementTypeEnumActivePower is ActivePower in mW.
	MeasurementTypeEnumActivePower MeasurementTypeEnum = 5
	// MeasurementTypeEnumReactivePower is ReactivePower in mVAR.
	MeasurementTypeEnumReactivePower MeasurementTypeEnum = 6
	// MeasurementTypeEnumApparentPower is ApparentPower in mVA.
	MeasurementTypeEnumApparentPower MeasurementTypeEnum = 7
	// MeasurementTypeEnumRMSVoltage is RMSVoltage in mV.
	MeasurementTypeEnumRMSVoltage MeasurementTypeEnum = 8
	// MeasurementTypeEnumRMSCurrent is RMSCurrent in mA.
	MeasurementTypeEnumRMSCurrent MeasurementTypeEnum = 9
	// MeasurementTypeEnumRMSPower is RMSPower in mW.
	MeasurementTypeEnumRMSPower MeasurementTypeEnum = 10
	// MeasurementTypeEnumFrequency is Frequency in mHz.
	MeasurementTypeEnumFrequency MeasurementTypeEnum = 11
	// MeasurementTypeEnumPowerFactor is PowerFactor.
	MeasurementTypeEnumPowerFactor MeasurementTypeEnum = 12
	// MeasurementTypeEnumNeutralCurrent is NeutralCurrent in mA.
	MeasurementTypeEnumNeutralCurrent MeasurementTypeEnum = 13
	// MeasurementTypeEnumElectricalEnergy is ElectricalEnergy in mWh.
	MeasurementTypeEnumElectricalEnergy MeasurementTypeEnum = 14
)

// LocationDescriptor (also known as locationdesc or LocationDescriptorStruct) describes a location.
type LocationDescriptor struct {
	// LocationName is the name of the location (e.g., "blue room").
	LocationName string // Tag 0

	// FloorNumber is the level number. 0 is the main floor, negative for basements.
	FloorNumber *int16 // Tag 1

	// AreaType is the ID of an area semantic tag from the Common Area Namespace.
	AreaType *Tag // Tag 2
}

// Encode converts the struct to a TLV structure.
func (s *LocationDescriptor) Encode() tlv.Struct {
	st := make(tlv.Struct)
	st[tlv.ContextTag(0)] = s.LocationName
	if s.FloorNumber != nil {
		st[tlv.ContextTag(1)] = int64(*s.FloorNumber)
	}
	if s.AreaType != nil {
		st[tlv.ContextTag(2)] = uint64(*s.AreaType)
	}
	return st
}

// Decode populates the struct from a TLV value.
func (s *LocationDescriptor) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected tlv.Struct, got %T", val)
	}
	if v, ok := st[tlv.ContextTag(0)]; ok {
		if sval, ok := v.(string); ok {
			s.LocationName = sval
		}
	}
	if v, ok := st[tlv.ContextTag(1)]; ok {
		if v == nil {
			s.FloorNumber = nil
		} else if ival, ok := v.(int64); ok {
			val := int16(ival)
			s.FloorNumber = &val
		}
	}
	if v, ok := st[tlv.ContextTag(2)]; ok {
		if v == nil {
			s.AreaType = nil
		} else if uval, ok := v.(uint64); ok {
			val := Tag(uval)
			s.AreaType = &val
		}
	}
	return nil
}
