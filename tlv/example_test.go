package tlv_test

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/etnz/matter/tlv"
)

// ExampleStruct demonstrates a struct with mixed types.
type ExampleStruct struct {
	Enabled bool
	ID      uint32
	Values  []int64
	Nested  NestedStruct
	List    []any
}

// NestedStruct is a sub-structure.
type NestedStruct struct {
	Name string
}

// Encode writes the struct to w using Matter TLV encoding.
func (s *ExampleStruct) Encode() tlv.Struct {
	st := tlv.Struct{
		tlv.ContextTag(0): s.Enabled,
		tlv.ContextTag(1): uint64(s.ID),
	}

	// Field 2: Values (Array of int64)
	var values tlv.IntArray
	for _, v := range s.Values {
		values = append(values, v)
	}
	st[tlv.ContextTag(2)] = values

	// Field 3: Nested (Struct)
	st[tlv.ContextTag(3)] = tlv.Struct{
		tlv.ContextTag(0): s.Nested.Name,
	}

	// Field 4: List (List of mixed types)
	var list tlv.List
	for _, item := range s.List {
		switch v := item.(type) {
		case bool:
			list = append(list, tlv.Element{Value: v})
		case string:
			list = append(list, tlv.Element{Value: v})
		}
	}
	st[tlv.ContextTag(4)] = list

	return st
}

// Decode reads the struct from r.
func (s *ExampleStruct) Decode(r io.Reader) error {
	val, err := tlv.Decode(r)
	if err != nil {
		return err
	}

	root, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected structure, got %T", val)
	}

	// Field 0: Enabled
	if v, ok := root[tlv.ContextTag(0)]; ok {
		if b, ok := v.(bool); ok {
			s.Enabled = b
		}
	}

	// Field 1: ID
	if v, ok := root[tlv.ContextTag(1)]; ok {
		if u, ok := v.(uint64); ok {
			s.ID = uint32(u)
		}
	}

	// Field 2: Values
	if v, ok := root[tlv.ContextTag(2)]; ok {
		if arr, ok := v.(tlv.IntArray); ok {
			s.Values = arr
		} else if arr, ok := v.(tlv.List); ok && len(arr) == 0 {
			s.Values = nil
		}
	}

	// Field 3: Nested
	if v, ok := root[tlv.ContextTag(3)]; ok {
		if nestedMap, ok := v.(tlv.Struct); ok {
			if name, ok := nestedMap[tlv.ContextTag(0)]; ok {
				if str, ok := name.(string); ok {
					s.Nested.Name = str
				}
			}
		}
	}

	// Field 4: List
	if v, ok := root[tlv.ContextTag(4)]; ok {
		if list, ok := v.(tlv.List); ok {
			s.List = make([]any, len(list))
			for i, e := range list {
				s.List[i] = e.Value
			}
		}
	}

	return nil
}

func TestExampleStruct(t *testing.T) {
	original := ExampleStruct{
		Enabled: true,
		ID:      0xCAFE,
		Values:  []int64{1, 2, 3, -4},
		Nested: NestedStruct{
			Name: "Matter",
		},
		List: []any{true, "Test"},
	}

	var buf bytes.Buffer
	buf.Write(original.Encode().Bytes())

	var decoded ExampleStruct
	if err := decoded.Decode(&buf); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if !reflect.DeepEqual(original, decoded) {
		t.Errorf("Mismatch:\nOriginal: %+v\nDecoded:  %+v", original, decoded)
	}
}
