package tlv

import (
	"bytes"
	"fmt"
	"reflect"
	"strconv"
)

// Marshal serializes a struct with "tlv" tags into TLV bytes.
func Marshal(v any) ([]byte, error) {
	val, err := toTLV(reflect.ValueOf(v))
	if err != nil {
		return nil, err
	}
	return Encode(val), nil
}

// Unmarshal deserializes TLV bytes into a struct with "tlv" tags.
func Unmarshal(data []byte, v any) error {
	val, err := Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("v must be a non-nil pointer")
	}
	return fromTLV(val, rv.Elem())
}

func toTLV(v reflect.Value) (any, error) {
	if !v.IsValid() {
		return nil, nil
	}

	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return nil, nil
		}
		return toTLV(v.Elem())
	case reflect.Struct:
		// Check if it's a tlv.Struct (map)
		if v.Type() == reflect.TypeOf(Struct{}) {
			return v.Interface(), nil
		}

		out := make(Struct)
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := t.Field(i)
			tagStr := field.Tag.Get("tlv")
			if tagStr == "" || tagStr == "-" {
				continue
			}
			tagNum, err := parseTag(tagStr)
			if err != nil {
				return nil, fmt.Errorf("field %s: %w", field.Name, err)
			}

			val, err := toTLV(v.Field(i))
			if err != nil {
				return nil, err
			}
			// Skip nil pointers (optional fields)
			if val == nil {
				continue
			}
			out[ContextTag(tagNum)] = val
		}
		return out, nil
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return v.Bytes(), nil
		}
		var l List
		for i := 0; i < v.Len(); i++ {
			val, err := toTLV(v.Index(i))
			if err != nil {
				return nil, err
			}
			l = append(l, Element{Tag: AnonymousTag, Value: val})
		}
		return l, nil
	default:
		return v.Interface(), nil
	}
}

func fromTLV(data any, v reflect.Value) error {
	if !v.CanSet() {
		return fmt.Errorf("cannot set value")
	}

	if data == nil {
		v.Set(reflect.Zero(v.Type()))
		return nil
	}

	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		return fromTLV(data, v.Elem())
	case reflect.Struct:
		st, ok := data.(Struct)
		if !ok {
			return fmt.Errorf("expected Struct, got %T", data)
		}
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := t.Field(i)
			tagStr := field.Tag.Get("tlv")
			if tagStr == "" || tagStr == "-" {
				continue
			}
			tagNum, err := parseTag(tagStr)
			if err != nil {
				return err
			}
			if val, ok := st[ContextTag(tagNum)]; ok {
				if err := fromTLV(val, v.Field(i)); err != nil {
					return err
				}
			}
		}
		return nil
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b, ok := data.([]byte)
			if !ok {
				return fmt.Errorf("expected []byte for byte slice, got %T", data)
			}
			v.SetBytes(b)
			return nil
		}
		// Handle List or Arrays
		var elements []any
		if l, ok := data.(List); ok {
			for _, e := range l {
				elements = append(elements, e.Value)
			}
		} else if arr, ok := asSlice(data); ok {
			elements = arr
		} else {
			return fmt.Errorf("expected List or Array, got %T", data)
		}

		slice := reflect.MakeSlice(v.Type(), len(elements), len(elements))
		for i, e := range elements {
			if err := fromTLV(e, slice.Index(i)); err != nil {
				return err
			}
		}
		v.Set(slice)
		return nil
	default:
		return setValue(v, data)
	}
}

func asSlice(data any) ([]any, bool) {
	// Helper to convert typed arrays to []any
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Slice {
		return nil, false
	}
	res := make([]any, val.Len())
	for i := 0; i < val.Len(); i++ {
		res[i] = val.Index(i).Interface()
	}
	return res, true
}

func setValue(v reflect.Value, data any) error {
	// Handle primitive conversions
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		var i int64
		switch d := data.(type) {
		case int64:
			i = d
		case uint64:
			i = int64(d)
		case int:
			i = int64(d)
		default:
			return fmt.Errorf("cannot assign %T to int", data)
		}
		v.SetInt(i)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		var u uint64
		switch d := data.(type) {
		case uint64:
			u = d
		case int64:
			u = uint64(d)
		case int:
			u = uint64(d)
		default:
			return fmt.Errorf("cannot assign %T to uint", data)
		}
		v.SetUint(u)
	case reflect.Bool:
		b, ok := data.(bool)
		if !ok {
			return fmt.Errorf("cannot assign %T to bool", data)
		}
		v.SetBool(b)
	case reflect.String:
		s, ok := data.(string)
		if !ok {
			return fmt.Errorf("cannot assign %T to string", data)
		}
		v.SetString(s)
	case reflect.Float32, reflect.Float64:
		var f float64
		switch d := data.(type) {
		case float64:
			f = d
		case float32:
			f = float64(d)
		default:
			return fmt.Errorf("cannot assign %T to float", data)
		}
		v.SetFloat(f)
	default:
		return fmt.Errorf("unsupported type %v", v.Kind())
	}
	return nil
}

func parseTag(tag string) (uint8, error) {
	v, err := strconv.ParseUint(tag, 0, 8)
	if err != nil {
		return 0, err
	}
	return uint8(v), nil
}
