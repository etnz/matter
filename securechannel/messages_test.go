package securechannel

import (
	"reflect"
	"testing"
)

func TestSecureChannel_EncodeDecode(t *testing.T) {
	t.Run("PBKDFParamRequest", func(t *testing.T) {
		in := pbkdfParamRequest{
			InitiatorRandom:    []byte("random12345678901234567890123456"),
			InitiatorSessionID: 0x1234,
			PasscodeID:         0x5678,
			HasPBKDFParameters: true,
			PBKDFParameters: &pbkdfParameters{
				Iterations: 1000,
				Salt:       []byte("salt123456789012"),
			},
		}
		encoded := in.Encode().Bytes()
		var out pbkdfParamRequest
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("PBKDFParamResponse", func(t *testing.T) {
		in := pbkdfParamResponse{
			InitiatorRandom:    []byte("init_random_32_bytes_long_string"),
			ResponderRandom:    []byte("resp_random_32_bytes_long_string"),
			ResponderSessionID: 0xABCD,
			PBKDFParameters: &pbkdfParameters{
				Iterations: 2000,
				Salt:       []byte("salt_16_bytes_xx"),
			},
		}
		encoded := in.Encode().Bytes()
		var out pbkdfParamResponse
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("Pake1", func(t *testing.T) {
		in := pake1{
			PA: []byte("public_key_a"),
		}
		encoded := in.Encode().Bytes()
		var out pake1
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("Pake2", func(t *testing.T) {
		in := pake2{
			PB: []byte("public_key_b"),
			CB: []byte("confirmation_b"),
		}
		encoded := in.Encode().Bytes()
		var out pake2
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("Pake3", func(t *testing.T) {
		in := pake3{
			CA: []byte("confirmation_a"),
		}
		encoded := in.Encode().Bytes()
		var out pake3
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("CASESigma1", func(t *testing.T) {
		in := caseSigma1{
			InitiatorRandom:    []byte("initiator_random"),
			InitiatorSessionID: 0x1111,
			DestinationID:      []byte("dest_id"),
			InitiatorEphPubKey: []byte("initiator_pub_key"),
			ResumptionID:       []byte("resumption_id"),
			ResumeMIC:          []byte("resume_mic"),
		}
		encoded := in.Encode().Bytes()
		var out caseSigma1
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("CASESigma2", func(t *testing.T) {
		in := caseSigma2{
			ResponderRandom:    []byte("responder_random"),
			ResponderSessionID: 0x2222,
			ResponderEphPubKey: []byte("responder_pub_key"),
			Encrypted:          []byte("encrypted_data"),
		}
		encoded := in.Encode().Bytes()
		var out caseSigma2
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("CASESigma2Signed", func(t *testing.T) {
		in := caseSigma2Signed{
			ResponderNOC:  []byte("responder_noc"),
			ResponderICAC: []byte("responder_icac"),
			Signature:     []byte("signature"),
			ResumptionID:  []byte("resumption_id"),
		}
		encoded := in.Encode().Bytes()
		var out caseSigma2Signed
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("CASESigma3", func(t *testing.T) {
		in := caseSigma3{
			Encrypted: []byte("encrypted_sigma3"),
		}
		encoded := in.Encode().Bytes()
		var out caseSigma3
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})

	t.Run("CASESigma3Signed", func(t *testing.T) {
		in := caseSigma3Signed{
			InitiatorNOC:  []byte("initiator_noc"),
			InitiatorICAC: []byte("initiator_icac"),
			Signature:     []byte("signature"),
		}
		encoded := in.Encode().Bytes()
		var out caseSigma3Signed
		if err := out.Decode(encoded); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Errorf("Mismatch:\nIn:  %+v\nOut: %+v", in, out)
		}
	})
}
