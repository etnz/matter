package tlv_test

import (
	"reflect"
	"testing"

	"github.com/etnz/matter/tlv"
)

type SubStruct struct {
	Val uint16 `tlv:"1"`
}

type AllTypes struct {
	B       bool        `tlv:"1"`
	I8      int8        `tlv:"2"`
	I16     int16       `tlv:"3"`
	I32     int32       `tlv:"4"`
	I64     int64       `tlv:"5"`
	U8      uint8       `tlv:"6"`
	U16     uint16      `tlv:"7"`
	U32     uint32      `tlv:"8"`
	U64     uint64      `tlv:"9"`
	F32     float32     `tlv:"10"`
	F64     float64     `tlv:"11"`
	Str     string      `tlv:"12"`
	Bytes   []byte      `tlv:"13"`
	Sub     SubStruct   `tlv:"14"`
	List    []uint32    `tlv:"15"`
	SubList []SubStruct `tlv:"16"`
	Opt     *uint32     `tlv:"17"`
	NilOpt  *uint32     `tlv:"18"`
}

func TestTagBasedMarshalUnmarshal(t *testing.T) {
	opt := uint32(999)
	input := AllTypes{
		B:       true,
		I8:      -8,
		I16:     -1616,
		I32:     -323232,
		I64:     -6464646464,
		U8:      8,
		U16:     1616,
		U32:     323232,
		U64:     6464646464,
		F32:     12.34,
		F64:     56.78,
		Str:     "test string",
		Bytes:   []byte{0x01, 0x02, 0x03},
		Sub:     SubStruct{Val: 123},
		List:    []uint32{1, 2, 3},
		SubList: []SubStruct{{Val: 1}, {Val: 2}},
		Opt:     &opt,
		NilOpt:  nil,
	}

	data, err := tlv.Marshal(&input)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var output AllTypes
	if err := tlv.Unmarshal(data, &output); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !reflect.DeepEqual(input, output) {
		t.Errorf("Mismatch:\nInput:  %+v\nOutput: %+v", input, output)
	}
}
