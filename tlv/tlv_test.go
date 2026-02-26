package tlv

import (
	"bytes"
	"reflect"
	"testing"
)

func TestPrimitives(t *testing.T) {
	tests := []struct {
		name      string
		write     func(w *bytes.Buffer) error
		expected  any
		expectTag Tag
	}{
		{
			name: "Bool True",
			write: func(w *bytes.Buffer) error {
				return WriteBool(w, ContextTag(1), true)
			},
			expected:  true,
			expectTag: ContextTag(1),
		},
		{
			name: "Bool False",
			write: func(w *bytes.Buffer) error {
				return WriteBool(w, ContextTag(2), false)
			},
			expected:  false,
			expectTag: ContextTag(2),
		},
		{
			name: "Null",
			write: func(w *bytes.Buffer) error {
				return WriteNull(w, ContextTag(3))
			},
			expected:  nil,
			expectTag: ContextTag(3),
		},
		{
			name: "Int8",
			write: func(w *bytes.Buffer) error {
				return WriteInt(w, ContextTag(4), -10)
			},
			expected:  int64(-10),
			expectTag: ContextTag(4),
		},
		{
			name: "Int16",
			write: func(w *bytes.Buffer) error {
				return WriteInt(w, ContextTag(5), -300)
			},
			expected:  int64(-300),
			expectTag: ContextTag(5),
		},
		{
			name: "Int32",
			write: func(w *bytes.Buffer) error {
				return WriteInt(w, ContextTag(6), -70000)
			},
			expected:  int64(-70000),
			expectTag: ContextTag(6),
		},
		{
			name: "Int64",
			write: func(w *bytes.Buffer) error {
				return WriteInt(w, ContextTag(7), -3000000000)
			},
			expected:  int64(-3000000000),
			expectTag: ContextTag(7),
		},
		{
			name: "UInt8",
			write: func(w *bytes.Buffer) error {
				return WriteUInt(w, ContextTag(8), 10)
			},
			expected:  uint64(10),
			expectTag: ContextTag(8),
		},
		{
			name: "UInt16",
			write: func(w *bytes.Buffer) error {
				return WriteUInt(w, ContextTag(9), 300)
			},
			expected:  uint64(300),
			expectTag: ContextTag(9),
		},
		{
			name: "UInt32",
			write: func(w *bytes.Buffer) error {
				return WriteUInt(w, ContextTag(10), 70000)
			},
			expected:  uint64(70000),
			expectTag: ContextTag(10),
		},
		{
			name: "UInt64",
			write: func(w *bytes.Buffer) error {
				return WriteUInt(w, ContextTag(11), 5000000000)
			},
			expected:  uint64(5000000000),
			expectTag: ContextTag(11),
		},
		{
			name: "Float32",
			write: func(w *bytes.Buffer) error {
				return WriteFloat32(w, ContextTag(12), 1.234)
			},
			expected:  float32(1.234),
			expectTag: ContextTag(12),
		},
		{
			name: "Float64",
			write: func(w *bytes.Buffer) error {
				return WriteFloat64(w, ContextTag(13), 1.23456789)
			},
			expected:  float64(1.23456789),
			expectTag: ContextTag(13),
		},
		{
			name: "UTF8",
			write: func(w *bytes.Buffer) error {
				return WriteUTF8(w, ContextTag(14), "hello world")
			},
			expected:  "hello world",
			expectTag: ContextTag(14),
		},
		{
			name: "OctetString",
			write: func(w *bytes.Buffer) error {
				return WriteOctetString(w, ContextTag(15), []byte{0x01, 0x02, 0x03})
			},
			expected:  []byte{0x01, 0x02, 0x03},
			expectTag: ContextTag(15),
		},
		{
			name: "Empty String",
			write: func(w *bytes.Buffer) error {
				return WriteUTF8(w, ContextTag(16), "")
			},
			expected:  "",
			expectTag: ContextTag(16),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.write(&buf); err != nil {
				t.Fatalf("Write failed: %v", err)
			}

			tag, val, err := decodeElement(&buf)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}

			if tag != tc.expectTag {
				t.Errorf("Tag mismatch: got %v, want %v", tag, tc.expectTag)
			}

			if tc.expected == nil {
				if val != nil {
					t.Errorf("Value mismatch: got %v, want nil", val)
				}
			} else {
				if !reflect.DeepEqual(val, tc.expected) {
					t.Errorf("Value mismatch: got %v (%T), want %v (%T)", val, val, tc.expected, tc.expected)
				}
			}
		})
	}
}

func TestContainers(t *testing.T) {
	t.Run("Structure", func(t *testing.T) {
		var buf bytes.Buffer
		tag := ContextTag(1)
		if err := WriteStruct(&buf, tag); err != nil {
			t.Fatal(err)
		}
		if err := WriteBool(&buf, ContextTag(0), true); err != nil {
			t.Fatal(err)
		}
		if err := WriteInt(&buf, ContextTag(1), 42); err != nil {
			t.Fatal(err)
		}
		if err := WriteEndOfContainer(&buf); err != nil {
			t.Fatal(err)
		}

		decodedTag, val, err := decodeElement(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if decodedTag != tag {
			t.Errorf("Tag mismatch: got %v, want %v", decodedTag, tag)
		}

		m, ok := val.(Struct)
		if !ok {
			t.Fatalf("Expected Struct, got %T", val)
		}

		if v, ok := m[ContextTag(0)]; !ok || v != true {
			t.Errorf("Field 0 mismatch: got %v, want true", v)
		}
		if v, ok := m[ContextTag(1)]; !ok || v != int64(42) {
			t.Errorf("Field 1 mismatch: got %v, want 42", v)
		}
	})

	t.Run("Array", func(t *testing.T) {
		var buf bytes.Buffer
		tag := ContextTag(2)
		if err := WriteArray(&buf, tag); err != nil {
			t.Fatal(err)
		}
		if err := WriteInt(&buf, AnonymousTag, 1); err != nil {
			t.Fatal(err)
		}
		if err := WriteInt(&buf, AnonymousTag, 2); err != nil {
			t.Fatal(err)
		}
		if err := WriteEndOfContainer(&buf); err != nil {
			t.Fatal(err)
		}

		decodedTag, val, err := decodeElement(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if decodedTag != tag {
			t.Errorf("Tag mismatch: got %v, want %v", decodedTag, tag)
		}

		arr, ok := val.(IntArray)
		if !ok {
			t.Fatalf("Expected IntArray, got %T", val)
		}
		if len(arr) != 2 || arr[0] != 1 || arr[1] != 2 {
			t.Errorf("Array mismatch: got %v", arr)
		}
	})

	t.Run("List", func(t *testing.T) {
		var buf bytes.Buffer
		tag := ContextTag(3)
		if err := WriteList(&buf, tag); err != nil {
			t.Fatal(err)
		}
		if err := WriteInt(&buf, AnonymousTag, 1); err != nil {
			t.Fatal(err)
		}
		if err := WriteBool(&buf, AnonymousTag, true); err != nil {
			t.Fatal(err)
		}
		if err := WriteEndOfContainer(&buf); err != nil {
			t.Fatal(err)
		}

		decodedTag, val, err := decodeElement(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if decodedTag != tag {
			t.Errorf("Tag mismatch: got %v, want %v", decodedTag, tag)
		}

		list, ok := val.(List)
		if !ok {
			t.Fatalf("Expected List, got %T", val)
		}
		if len(list) != 2 {
			t.Fatalf("List length mismatch")
		}
		if list[0].Value != int64(1) {
			t.Errorf("Element 0 mismatch: got %v", list[0].Value)
		}
		if list[1].Value != true {
			t.Errorf("Element 1 mismatch: got %v", list[1].Value)
		}
	})
}

func TestTags(t *testing.T) {
	// Test different tag types
	tests := []struct {
		name string
		tag  Tag
	}{
		{"Anonymous", AnonymousTag},
		{"Context", ContextTag(0x12)},
		{"CommonProfile", CommonProfileTag(0x1234)},
		{"ImplicitProfile", ImplicitProfileTag(0x12345678)},
		{"FullyQualified6", FullyQualifiedTag6(0x1234, 0x5678, 0x9abc)},
		{"FullyQualified8", FullyQualifiedTag8(0x1234, 0x5678, 0x9abcdef0)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteNull(&buf, tc.tag); err != nil {
				t.Fatal(err)
			}
			decodedTag, _, err := decodeElement(&buf)
			if err != nil {
				t.Fatal(err)
			}
			if decodedTag != tc.tag {
				t.Errorf("Tag mismatch: got %v, want %v", decodedTag, tc.tag)
			}
		})
	}
}
