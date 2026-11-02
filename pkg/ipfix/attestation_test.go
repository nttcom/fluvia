package ipfix

import (
	"encoding/base64"
	"testing"
)

func sampleMessageBytes() []byte {
	m := Message{Version: 10, SequenceNumber: 1, ObservationDomainID: 1}
	return m.Serialize()
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	data := sampleMessageBytes()
	for _, algorithm := range SupportedAlgorithms {
		pub, priv, err := GenerateKey(algorithm)
		if err != nil {
			t.Fatalf("%s generate key: %v", algorithm, err)
		}

		att, err := SignBytes(data, algorithm, priv)
		if err != nil {
			t.Fatalf("%s sign: %v", algorithm, err)
		}
		if att.Issuer != Issuer || att.Algorithm != algorithm {
			t.Fatalf("%s unexpected attestation header %+v", algorithm, att)
		}

		ok, err := VerifyBytes(data, att, nil)
		if err != nil || !ok {
			t.Fatalf("%s verify failed ok=%v err=%v", algorithm, ok, err)
		}

		pubBytes, err := pub.MarshalBinary()
		if err != nil {
			t.Fatalf("%s marshal pub: %v", algorithm, err)
		}
		ok, err = VerifyBytes(data, att, pubBytes)
		if err != nil || !ok {
			t.Fatalf("%s pinned verify failed ok=%v err=%v", algorithm, ok, err)
		}
	}
}

func TestDetectsTamperedBytes(t *testing.T) {
	data := sampleMessageBytes()
	att, err := SignBytes(data, DefaultAlgorithm, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[0] ^= 0x01

	ok, err := VerifyBytes(tampered, att, nil)
	if err != nil {
		t.Fatalf("verify err: %v", err)
	}
	if ok {
		t.Fatal("tampered bytes were accepted")
	}
}

func TestRejectsWrongSigner(t *testing.T) {
	data := sampleMessageBytes()
	att, err := SignBytes(data, DefaultAlgorithm, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	otherPub, _, err := GenerateKey(DefaultAlgorithm)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	otherPubBytes, err := otherPub.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal other pub: %v", err)
	}

	ok, err := VerifyBytes(data, att, otherPubBytes)
	if err != nil {
		t.Fatalf("verify err: %v", err)
	}
	if ok {
		t.Fatal("wrong signer was accepted")
	}
}

func TestRejectsUnknownAlgorithm(t *testing.T) {
	if _, err := SignBytes(sampleMessageBytes(), "ML-DSA-99", nil); err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
}

func TestAttestationJSON(t *testing.T) {
	att, err := SignBytes(sampleMessageBytes(), DefaultAlgorithm, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := att.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(att.Signature); err != nil {
		t.Fatalf("signature is not valid base64: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("empty json")
	}
}
