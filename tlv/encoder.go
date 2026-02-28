package tlv

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

// Element Types
const (
	typeSignedInt1     = 0x00
	typeSignedInt2     = 0x01
	typeSignedInt4     = 0x02
	typeSignedInt8     = 0x03
	typeUnsignedInt1   = 0x04
	typeUnsignedInt2   = 0x05
	typeUnsignedInt4   = 0x06
	typeUnsignedInt8   = 0x07
	typeBooleanFalse   = 0x08
	typeBooleanTrue    = 0x09
	typeFloat4         = 0x0A
	typeFloat8         = 0x0B
	typeUTF8String1    = 0x0C
	typeUTF8String2    = 0x0D
	typeUTF8String4    = 0x0E
	typeUTF8String8    = 0x0F
	typeOctetString1   = 0x10
	typeOctetString2   = 0x11
	typeOctetString4   = 0x12
	typeOctetString8   = 0x13
	typeNull           = 0x14
	typeStructure      = 0x15
	typeArray          = 0x16
	typeList           = 0x17
	typeEndOfContainer = 0x18
)

// Encode serializes a TLV tree node into bytes.
// It ensures deterministic encoding by sorting Structure fields by tag (Canonical Encoding).
func Encode(v any) []byte {
	var buf bytes.Buffer
	if err := encodeValue(&buf, AnonymousTag, v); err != nil {
		panic(err) // Should not happen with bytes.Buffer
	}
	return buf.Bytes()
}

func (s Struct) Bytes() []byte {
	return Encode(s)
}

func (l List) Bytes() []byte {
	return Encode(l)
}

func (a IntArray) Bytes() []byte {
	return Encode(a)
}

func (a UintArray) Bytes() []byte {
	return Encode(a)
}

func (a BoolArray) Bytes() []byte {
	return Encode(a)
}

func (a FloatArray) Bytes() []byte {
	return Encode(a)
}

func (a DoubleArray) Bytes() []byte {
	return Encode(a)
}

func (a StringArray) Bytes() []byte {
	return Encode(a)
}

func (a OctetStringArray) Bytes() []byte {
	return Encode(a)
}

func (a StructArray) Bytes() []byte {
	return Encode(a)
}

func encodeValue(w io.Writer, tag Tag, v any) error {
	switch val := v.(type) {
	case nil:
		return WriteNull(w, tag)
	case bool:
		return WriteBool(w, tag, val)
	case int:
		return WriteInt(w, tag, int64(val))
	case int8:
		return WriteInt(w, tag, int64(val))
	case int16:
		return WriteInt(w, tag, int64(val))
	case int32:
		return WriteInt(w, tag, int64(val))
	case int64:
		return WriteInt(w, tag, val)
	case uint:
		return WriteUInt(w, tag, uint64(val))
	case uint8:
		return WriteUInt(w, tag, uint64(val))
	case uint16:
		return WriteUInt(w, tag, uint64(val))
	case uint32:
		return WriteUInt(w, tag, uint64(val))
	case uint64:
		return WriteUInt(w, tag, val)
	case float32:
		return WriteFloat32(w, tag, val)
	case float64:
		return WriteFloat64(w, tag, val)
	case string:
		return WriteUTF8(w, tag, val)
	case []byte:
		return WriteOctetString(w, tag, val)
	case Struct:
		if err := WriteStruct(w, tag); err != nil {
			return err
		}
		keys := make([]Tag, 0, len(val))
		for t := range val {
			keys = append(keys, t)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].Control != keys[j].Control {
				return keys[i].Control < keys[j].Control
			}
			return bytes.Compare(keys[i].Value[:], keys[j].Value[:]) < 0
		})
		for _, t := range keys {
			if err := encodeValue(w, t, val[t]); err != nil {
				return err
			}
		}
		return WriteEndOfContainer(w)
	case List:
		if err := WriteList(w, tag); err != nil {
			return err
		}
		for _, e := range val {
			if err := encodeValue(w, e.Tag, e.Value); err != nil {
				return err
			}
		}
		return WriteEndOfContainer(w)
	case IntArray:
		return encodeArray(w, tag, val)
	case UintArray:
		return encodeArray(w, tag, val)
	case BoolArray:
		return encodeArray(w, tag, val)
	case FloatArray:
		return encodeArray(w, tag, val)
	case DoubleArray:
		return encodeArray(w, tag, val)
	case StringArray:
		return encodeArray(w, tag, val)
	case OctetStringArray:
		return encodeArray(w, tag, val)
	case StructArray:
		return encodeArray(w, tag, val)
	case []List:
		return encodeArray(w, tag, val)
	default:
		return fmt.Errorf("unsupported type %T", v)
	}
}

func encodeArray[T any](w io.Writer, tag Tag, arr []T) error {
	if err := WriteArray(w, tag); err != nil {
		return err
	}
	for _, v := range arr {
		if err := encodeValue(w, AnonymousTag, v); err != nil {
			return err
		}
	}
	return WriteEndOfContainer(w)
}

func writeControlAndTag(w io.Writer, elementType uint8, tag Tag) error {
	control := (uint8(tag.Control) << 5) | (elementType & 0x1F)
	if _, err := w.Write([]byte{control}); err != nil {
		return err
	}
	var l int
	switch tag.Control {
	case TagControlAnonymous:
		l = 0
	case TagControlContextSpecific:
		l = 1
	case TagControlCommonProfile:
		l = 2
	case TagControlImplicitProfile:
		l = 4
	case TagControlFullyQualified6:
		l = 6
	case TagControlFullyQualified8:
		l = 8
	}
	if l > 0 {
		if _, err := w.Write(tag.Value[:l]); err != nil {
			return err
		}
	}
	return nil
}

// WriteBool writes a boolean value to the io.Writer.
// The True or False value is completely encoded inside the Control Octet's Element Type bits.
// No Length or Value fields are written.
func WriteBool(w io.Writer, tag Tag, value bool) error {
	if value {
		return writeControlAndTag(w, typeBooleanTrue, tag)
	}
	return writeControlAndTag(w, typeBooleanFalse, tag)
}

// WriteNull writes a null value to the io.Writer.
// "Null" is a specific Element Type. Only the Control Octet (and Tag) is written
// to indicate the intentional absence of a value.
func WriteNull(w io.Writer, tag Tag) error {
	return writeControlAndTag(w, typeNull, tag)
}

// WriteInt writes a signed integer to the io.Writer.
// The Element Type bits specify whether the integer is Signed and whether its payload
// is 1, 2, 4, or 8 bytes long. The integer is written in little-endian byte order.
// The smallest byte width that can hold the value is selected to optimize size.
func WriteInt(w io.Writer, tag Tag, value int64) error {
	if value >= -128 && value <= 127 {
		if err := writeControlAndTag(w, typeSignedInt1, tag); err != nil {
			return err
		}
		_, err := w.Write([]byte{byte(value)})
		return err
	}
	if value >= -32768 && value <= 32767 {
		if err := writeControlAndTag(w, typeSignedInt2, tag); err != nil {
			return err
		}
		return binary.Write(w, binary.LittleEndian, int16(value))
	}
	if value >= -2147483648 && value <= 2147483647 {
		if err := writeControlAndTag(w, typeSignedInt4, tag); err != nil {
			return err
		}
		return binary.Write(w, binary.LittleEndian, int32(value))
	}
	if err := writeControlAndTag(w, typeSignedInt8, tag); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, value)
}

// WriteUInt writes an unsigned integer to the io.Writer.
// The Element Type bits specify whether the integer is Unsigned and whether its payload
// is 1, 2, 4, or 8 bytes long. The integer is written in little-endian byte order.
// The smallest byte width that can hold the value is selected to optimize size.
func WriteUInt(w io.Writer, tag Tag, value uint64) error {
	if value <= 255 {
		if err := writeControlAndTag(w, typeUnsignedInt1, tag); err != nil {
			return err
		}
		_, err := w.Write([]byte{byte(value)})
		return err
	}
	if value <= 65535 {
		if err := writeControlAndTag(w, typeUnsignedInt2, tag); err != nil {
			return err
		}
		return binary.Write(w, binary.LittleEndian, uint16(value))
	}
	if value <= 4294967295 {
		if err := writeControlAndTag(w, typeUnsignedInt4, tag); err != nil {
			return err
		}
		return binary.Write(w, binary.LittleEndian, uint32(value))
	}
	if err := writeControlAndTag(w, typeUnsignedInt8, tag); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, value)
}

// WriteFloat32 writes a single precision floating point number to the io.Writer.
// The Element Type bits specify Single Precision. The value is written as a 4-byte
// IEEE 754 formatted value in little-endian order.
func WriteFloat32(w io.Writer, tag Tag, value float32) error {
	if err := writeControlAndTag(w, typeFloat4, tag); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, value)
}

// WriteFloat64 writes a double precision floating point number to the io.Writer.
// The Element Type bits specify Double Precision. The value is written as an 8-byte
// IEEE 754 formatted value in little-endian order.
func WriteFloat64(w io.Writer, tag Tag, value float64) error {
	if err := writeControlAndTag(w, typeFloat8, tag); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, value)
}

// WriteUTF8 writes a UTF-8 string to the io.Writer.
// Strings write a Length field to the wire. The Element Type bits specify UTF-8
// and whether the Length field takes up 1, 2, 4, or 8 bytes.
// The byte-length of the string is written into the Length field (little-endian),
// followed immediately by the raw string bytes.
func WriteUTF8(w io.Writer, tag Tag, value string) error {
	length := len(value)
	var typeCode uint8
	if length <= 255 {
		typeCode = typeUTF8String1
	} else if length <= 65535 {
		typeCode = typeUTF8String2
	} else if uint64(length) <= 4294967295 {
		typeCode = typeUTF8String4
	} else {
		typeCode = typeUTF8String8
	}

	if err := writeControlAndTag(w, typeCode, tag); err != nil {
		return err
	}

	switch typeCode {
	case typeUTF8String1:
		if _, err := w.Write([]byte{byte(length)}); err != nil {
			return err
		}
	case typeUTF8String2:
		if err := binary.Write(w, binary.LittleEndian, uint16(length)); err != nil {
			return err
		}
	case typeUTF8String4:
		if err := binary.Write(w, binary.LittleEndian, uint32(length)); err != nil {
			return err
		}
	case typeUTF8String8:
		if err := binary.Write(w, binary.LittleEndian, uint64(length)); err != nil {
			return err
		}
	}

	if length > 0 {
		_, err := io.WriteString(w, value)
		return err
	}
	return nil
}

// WriteOctetString writes an octet string to the io.Writer.
// Strings write a Length field to the wire. The Element Type bits specify Octet String
// and whether the Length field takes up 1, 2, 4, or 8 bytes.
// The byte-length of the string is written into the Length field (little-endian),
// followed immediately by the raw bytes.
func WriteOctetString(w io.Writer, tag Tag, value []byte) error {
	length := len(value)
	var typeCode uint8
	if length <= 255 {
		typeCode = typeOctetString1
	} else if length <= 65535 {
		typeCode = typeOctetString2
	} else if uint64(length) <= 4294967295 {
		typeCode = typeOctetString4
	} else {
		typeCode = typeOctetString8
	}

	if err := writeControlAndTag(w, typeCode, tag); err != nil {
		return err
	}

	switch typeCode {
	case typeOctetString1:
		if _, err := w.Write([]byte{byte(length)}); err != nil {
			return err
		}
	case typeOctetString2:
		if err := binary.Write(w, binary.LittleEndian, uint16(length)); err != nil {
			return err
		}
	case typeOctetString4:
		if err := binary.Write(w, binary.LittleEndian, uint32(length)); err != nil {
			return err
		}
	case typeOctetString8:
		if err := binary.Write(w, binary.LittleEndian, uint64(length)); err != nil {
			return err
		}
	}

	if length > 0 {
		_, err := w.Write(value)
		return err
	}
	return nil
}

// WriteStruct writes the start of a structure to the io.Writer.
// Structures do not have a predetermined length. They encapsulate a sequence of
// fully formed TLV elements and are closed by a specific termination marker.
// Every nested element in a Struct MUST have a Context-Specific or Fully-Qualified Tag.
func WriteStruct(w io.Writer, tag Tag) error {
	return writeControlAndTag(w, typeStructure, tag)
}

// WriteArray writes the start of an array to the io.Writer.
// Arrays do not have a predetermined length. They encapsulate a sequence of
// fully formed TLV elements and are closed by a specific termination marker.
// Every nested element in an Array MUST be of the same data type and MUST use Anonymous (omitted) tags.
func WriteArray(w io.Writer, tag Tag) error {
	return writeControlAndTag(w, typeArray, tag)
}

// WriteList writes the start of a list to the io.Writer.
// Lists do not have a predetermined length. They encapsulate a sequence of
// fully formed TLV elements and are closed by a specific termination marker.
// Lists can contain mixed types and a mix of Anonymous or Context-Specific tags.
func WriteList(w io.Writer, tag Tag) error {
	return writeControlAndTag(w, typeList, tag)
}

// WriteEndOfContainer writes the end of container marker to the io.Writer.
// To close a Struct, Array, or List, a single Control Octet with a specific
// Element Type (0x18) and an Anonymous Tag Control (000b) is written.
// It has no Tag, no Length, and no Value.
func WriteEndOfContainer(w io.Writer) error {
	return writeControlAndTag(w, typeEndOfContainer, AnonymousTag)
}
