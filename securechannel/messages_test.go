package securechannel

import (
	"reflect"
	"testing"
)

func TestSecureChannel_EncodeDecode(t *testing.T) {
	t.Run("PBKDFParamRequest", func(t *testing.T) {
		in := PBKDFParamRequest{
			InitiatorRandom:    []byte("random12345678901234567890123456"),
			InitiatorSessionID: 0x1234,
			PasscodeID:         0x5678,
			HasPBKDFParameters: true,
			PBKDFParameters: &PBKDFParameters{
				Iterations: 1000,
				Salt:       []byte("salt123456789012"),
			},
		}
		encoded := in.Encode().Bytes()
		var out PBKDFParamRequest
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("PBKDFParamResponse", func(t *testing.T) {
		in := PBKDFParamResponse{
			InitiatorRandom:    []byte("init_random_32_bytes_long_string"),
			ResponderRandom:    []byte("resp_random_32_bytes_long_string"),
			ResponderSessionID: 0xABCD,
			PBKDFParameters: &PBKDFParameters{
				Iterations: 2000,
				Salt:       []byte("salt_16_bytes_xx"),
			},
		}
		encoded := in.Encode().Bytes()
		var out PBKDFParamResponse
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("Pake1", func(t *testing.T) {
		in := Pake1{
			PA: []byte("public_key_a"),
		}
		encoded := in.Encode().Bytes()
		var out Pake1
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("Pake2", func(t *testing.T) {
		in := Pake2{
			PB: []byte("public_key_b"),
			CB: []byte("confirmation_b"),
		}
		encoded := in.Encode().Bytes()
		var out Pake2
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("Pake3", func(t *testing.T) {
		in := Pake3{
			CA: []byte("confirmation_a"),
		}
		encoded := in.Encode().Bytes()
		var out Pake3
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("CASESigma1", func(t *testing.T) {
		in := CASESigma1{
			InitiatorRandom:    []byte("initiator_random"),
			InitiatorSessionID: 0x1111,
			DestinationID:      []byte("dest_id"),
			InitiatorEphPubKey: []byte("initiator_pub_key"),
			ResumptionID:       []byte("resumption_id"),
			ResumeMIC:          []byte("resume_mic"),
		}
		encoded := in.Encode().Bytes()
		var out CASESigma1
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("CASESigma2", func(t *testing.T) {
		in := CASESigma2{
			ResponderRandom:    []byte("responder_random"),
			ResponderSessionID: 0x2222,
			ResponderEphPubKey: []byte("responder_pub_key"),
			Encrypted:          []byte("encrypted_data"),
		}
		encoded := in.Encode().Bytes()
		var out CASESigma2
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("CASESigma2Signed", func(t *testing.T) {
		in := CASESigma2Signed{
			ResponderNOC:  []byte("responder_noc"),
			ResponderICAC: []byte("responder_icac"),
			Signature:     []byte("signature"),
			ResumptionID:  []byte("resumption_id"),
		}
		encoded := in.Encode().Bytes()
		var out CASESigma2Signed
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("CASESigma3", func(t *testing.T) {
		in := CASESigma3{
			Encrypted: []byte("encrypted_sigma3"),
		}
		encoded := in.Encode().Bytes()
		var out CASESigma3
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("CASESigma3Signed", func(t *testing.T) {
		in := CASESigma3Signed{
			InitiatorNOC:  []byte("initiator_noc"),
			InitiatorICAC: []byte("initiator_icac"),
			Signature:     []byte("signature"),
		}
		encoded := in.Encode().Bytes()
		var out CASESigma3Signed
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})
}
