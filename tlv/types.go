package tlv

import "encoding/binary"

// TagControl defines the type of the tag.
type TagControl uint8

const (
	TagControlAnonymous       TagControl = 0
	TagControlContextSpecific TagControl = 1
	TagControlCommonProfile   TagControl = 2
	TagControlImplicitProfile TagControl = 3
	TagControlFullyQualified6 TagControl = 4 // 6 bytes: Vendor(2) + Profile(2) + Tag(2)
	TagControlFullyQualified8 TagControl = 5 // 8 bytes: Vendor(2) + Profile(2) + Tag(4)
)

// Tag represents a TLV tag.
type Tag struct {
	Control TagControl
	Value   [8]byte
}

// AnonymousTag is a tag with no value.
var AnonymousTag = Tag{}

// ContextTag creates a context-specific tag.
func ContextTag(id uint8) Tag {
	var b [8]byte
	b[0] = id
	return Tag{Control: TagControlContextSpecific, Value: b}
}

// CommonProfileTag creates a common profile tag.
func CommonProfileTag(id uint16) Tag {
	var b [8]byte
	binary.LittleEndian.PutUint16(b[:], id)
	return Tag{Control: TagControlCommonProfile, Value: b}
}

// ImplicitProfileTag creates an implicit profile tag.
func ImplicitProfileTag(id uint32) Tag {
	var b [8]byte
	binary.LittleEndian.PutUint32(b[:], id)
	return Tag{Control: TagControlImplicitProfile, Value: b}
}

// FullyQualifiedTag6 creates a fully qualified tag with 16-bit tag number.
func FullyQualifiedTag6(vendorID uint16, profileNum uint16, tagNum uint16) Tag {
	var b [8]byte
	binary.LittleEndian.PutUint16(b[0:], vendorID)
	binary.LittleEndian.PutUint16(b[2:], profileNum)
	binary.LittleEndian.PutUint16(b[4:], tagNum)
	return Tag{Control: TagControlFullyQualified6, Value: b}
}

// FullyQualifiedTag8 creates a fully qualified tag with 32-bit tag number.
func FullyQualifiedTag8(vendorID uint16, profileNum uint16, tagNum uint32) Tag {
	var b [8]byte
	binary.LittleEndian.PutUint16(b[0:], vendorID)
	binary.LittleEndian.PutUint16(b[2:], profileNum)
	binary.LittleEndian.PutUint32(b[4:], tagNum)
	return Tag{Control: TagControlFullyQualified8, Value: b}
}

// Struct represents a TLV Structure.
type Struct map[Tag]any

// Element represents a TLV element with a tag and a value.
type Element struct {
	Tag   Tag
	Value any
}

// List represents a TLV List.
type List []Element

// Array types
type IntArray []int64
type UintArray []uint64
type BoolArray []bool
type FloatArray []float32
type DoubleArray []float64
type StringArray []string
type OctetStringArray [][]byte
type OctetString []byte
type StructArray []Struct
