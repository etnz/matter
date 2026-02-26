package tlv

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Decode reads a TLV element from r and returns its value.
//
// Mappings:
// - Integers: int64 or uint64
// - Boolean: bool
// - Floating Point: float32 or float64
// - UTF8 String: string
// - Octet String: []byte
// - Null: nil
// - Structure: Struct (map[Tag]any)
// - Array: IntArray, UintArray, etc.
// - List: List ([]Element)
func Decode(r io.Reader) (any, error) {
	_, val, err := decodeElement(r)
	return val, err
}

var errEndOfContainer = fmt.Errorf("end of container")

func decodeElement(r io.Reader) (Tag, any, error) {
	// Read Control Octet
	var controlBuf [1]byte
	if _, err := io.ReadFull(r, controlBuf[:]); err != nil {
		return Tag{}, nil, err
	}
	control := controlBuf[0]
	tagControl := TagControl(control >> 5)
	elementType := control & 0x1F

	// Read Tag
	var tag Tag
	tag.Control = tagControl

	var tagLen int
	switch tagControl {
	case TagControlAnonymous:
		tagLen = 0
	case TagControlContextSpecific:
		tagLen = 1
	case TagControlCommonProfile:
		tagLen = 2
	case TagControlImplicitProfile:
		tagLen = 4
	case TagControlFullyQualified6:
		tagLen = 6
	case TagControlFullyQualified8:
		tagLen = 8
	}

	if tagLen > 0 {
		if _, err := io.ReadFull(r, tag.Value[:tagLen]); err != nil {
			return Tag{}, nil, err
		}
	}

	val, err := decodeValue(r, elementType)
	return tag, val, err
}

func decodeValue(r io.Reader, elementType uint8) (any, error) {
	switch elementType {
	case typeSignedInt1:
		var val int8
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return nil, err
		}
		return int64(val), nil
	case typeSignedInt2:
		var val int16
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return nil, err
		}
		return int64(val), nil
	case typeSignedInt4:
		var val int32
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return nil, err
		}
		return int64(val), nil
	case typeSignedInt8:
		var val int64
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return nil, err
		}
		return val, nil
	case typeUnsignedInt1:
		var val uint8
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return nil, err
		}
		return uint64(val), nil
	case typeUnsignedInt2:
		var val uint16
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return nil, err
		}
		return uint64(val), nil
	case typeUnsignedInt4:
		var val uint32
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return nil, err
		}
		return uint64(val), nil
	case typeUnsignedInt8:
		var val uint64
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return nil, err
		}
		return val, nil
	case typeBooleanFalse:
		return false, nil
	case typeBooleanTrue:
		return true, nil
	case typeFloat4:
		var val float32
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return nil, err
		}
		return val, nil
	case typeFloat8:
		var val float64
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			return nil, err
		}
		return val, nil
	case typeUTF8String1:
		return readString(r, 1)
	case typeUTF8String2:
		return readString(r, 2)
	case typeUTF8String4:
		return readString(r, 4)
	case typeUTF8String8:
		return readString(r, 8)
	case typeOctetString1:
		return readOctetString(r, 1)
	case typeOctetString2:
		return readOctetString(r, 2)
	case typeOctetString4:
		return readOctetString(r, 4)
	case typeOctetString8:
		return readOctetString(r, 8)
	case typeNull:
		return nil, nil
	case typeStructure:
		return decodeStructure(r)
	case typeArray:
		return decodeArray(r)
	case typeList:
		return decodeList(r)
	case typeEndOfContainer:
		return nil, errEndOfContainer
	default:
		return nil, fmt.Errorf("unknown element type: 0x%x", elementType)
	}
}

func readLength(r io.Reader, size int) (uint64, error) {
	switch size {
	case 1:
		var l uint8
		if err := binary.Read(r, binary.LittleEndian, &l); err != nil {
			return 0, err
		}
		return uint64(l), nil
	case 2:
		var l uint16
		if err := binary.Read(r, binary.LittleEndian, &l); err != nil {
			return 0, err
		}
		return uint64(l), nil
	case 4:
		var l uint32
		if err := binary.Read(r, binary.LittleEndian, &l); err != nil {
			return 0, err
		}
		return uint64(l), nil
	case 8:
		var l uint64
		if err := binary.Read(r, binary.LittleEndian, &l); err != nil {
			return 0, err
		}
		return l, nil
	}
	return 0, fmt.Errorf("invalid length size")
}

func readString(r io.Reader, lenSize int) (string, error) {
	l, err := readLength(r, lenSize)
	if err != nil {
		return "", err
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func readOctetString(r io.Reader, lenSize int) ([]byte, error) {
	l, err := readLength(r, lenSize)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func decodeStructure(r io.Reader) (Struct, error) {
	m := make(Struct)
	for {
		tag, val, err := decodeElement(r)
		if err == errEndOfContainer {
			return m, nil
		}
		if err != nil {
			return nil, err
		}
		m[tag] = val
	}
}

func decodeList(r io.Reader) (List, error) {
	var l List
	for {
		tag, val, err := decodeElement(r)
		if err == errEndOfContainer {
			return l, nil
		}
		if err != nil {
			return nil, err
		}
		l = append(l, Element{Tag: tag, Value: val})
	}
}

func decodeArray(r io.Reader) (any, error) {
	var elements []any
	for {
		_, val, err := decodeElement(r)
		if err == errEndOfContainer {
			break
		}
		if err != nil {
			return nil, err
		}
		elements = append(elements, val)
	}

	if len(elements) == 0 {
		return []any{}, nil
	}

	// Attempt to convert to specific type slice
	switch elements[0].(type) {
	case int64:
		res := make(IntArray, len(elements))
		for i, e := range elements {
			v, ok := e.(int64)
			if !ok {
				return elements, nil
			}
			res[i] = v
		}
		return res, nil
	case uint64:
		res := make(UintArray, len(elements))
		for i, e := range elements {
			v, ok := e.(uint64)
			if !ok {
				return elements, nil
			}
			res[i] = v
		}
		return res, nil
	case bool:
		res := make(BoolArray, len(elements))
		for i, e := range elements {
			v, ok := e.(bool)
			if !ok {
				return elements, nil
			}
			res[i] = v
		}
		return res, nil
	case float32:
		res := make(FloatArray, len(elements))
		for i, e := range elements {
			v, ok := e.(float32)
			if !ok {
				return elements, nil
			}
			res[i] = v
		}
		return res, nil
	case float64:
		res := make(DoubleArray, len(elements))
		for i, e := range elements {
			v, ok := e.(float64)
			if !ok {
				return elements, nil
			}
			res[i] = v
		}
		return res, nil
	case string:
		res := make(StringArray, len(elements))
		for i, e := range elements {
			v, ok := e.(string)
			if !ok {
				return elements, nil
			}
			res[i] = v
		}
		return res, nil
	case []byte:
		res := make(OctetStringArray, len(elements))
		for i, e := range elements {
			v, ok := e.([]byte)
			if !ok {
				return elements, nil
			}
			res[i] = v
		}
		return res, nil
	case Struct:
		res := make(StructArray, len(elements))
		for i, e := range elements {
			v, ok := e.(Struct)
			if !ok {
				return elements, nil
			}
			res[i] = v
		}
		return res, nil
	case List:
		res := make([]List, len(elements))
		for i, e := range elements {
			v, ok := e.(List)
			if !ok {
				return elements, nil
			}
			res[i] = v
		}
		return res, nil
	default:
		return elements, nil
	}
}
