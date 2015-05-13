package jcc

import (
	"github.com/ronperry/cryptoedge/eccutil"
	"encoding/hex"
	"math/big"
	"testing"
)

func Test_BlindingParamClient(t *testing.T) {
	p := new(eccutil.Point)
	p.X, p.Y = new(big.Int), new(big.Int)
	n := NewBlindingParamClient(p)
	b, err := n.Marshal()
	if err != nil {
		t.Fatalf("Marshalling failed: %s", err)
	}
	_, err = n.Unmarshal(b)
	if err != nil {
		t.Fatalf("UnMarshalling failed: %s", err)
	}
	n.PubKey.X = big.NewInt(3)
	_, err = n.Unmarshal(b)
	if err == nil {
		t.Fatal("UnMarshalling must fail for foreign signer")
	}
}

func Test_ClearMessage(t *testing.T) {
	n := NewClearMessage([]byte("Some message to test"))
	b, err := n.Marshal()
	if err != nil {
		t.Fatalf("Marshalling failed: %s", err)
	}
	_, err = n.Unmarshal(b)
	if err != nil {
		t.Fatalf("UnMarshalling failed: %s", err)
	}
	if "bd328d95d29d43e1c1c11eaf6ad9502dc039fc9b5e7813cefa001b3dfd3bbcda" != hex.EncodeToString(n.UniqueID()) {
		t.Error("Unique ID Wrong")
	}
}

func Test_BlindingFactors(t *testing.T) {
	p := new(eccutil.Point)
	p.X, p.Y = new(big.Int), new(big.Int)
	n := NewBlindingFactors(p)
	b, err := n.Marshal()
	if err != nil {
		t.Fatalf("Marshalling failed: %s", err)
	}
	_, err = n.Unmarshal(b)
	if err != nil {
		t.Fatalf("UnMarshalling failed: %s", err)
	}
	n.PubKey.X = big.NewInt(3)
	_, err = n.Unmarshal(b)
	if err == nil {
		t.Fatal("UnMarshalling must fail for foreign signer")
	}
}

func Test_BlindMessage(t *testing.T) {
	p := new(eccutil.Point)
	p.X, p.Y = new(big.Int), new(big.Int)
	n := NewBlindMessage(p)
	n.Message.X, n.Message.Y = new(big.Int), new(big.Int)
	b, err := n.Marshal()
	if err != nil {
		t.Fatalf("Marshalling failed: %s", err)
	}
	_, err = n.Unmarshal(b)
	if err != nil {
		t.Fatalf("UnMarshalling failed: %s", err)
	}
	n.PubKey.X = big.NewInt(3)
	_, err = n.Unmarshal(b)
	if err == nil {
		t.Fatal("UnMarshalling must fail for foreign signer")
	}
}

func Test_BlindSignature(t *testing.T) {
	p := new(eccutil.Point)
	p.X, p.Y = new(big.Int), new(big.Int)
	n := NewBlindSignature(p)
	n.R.X, n.R.Y = new(big.Int), new(big.Int)
	n.S.X, n.S.Y = new(big.Int), new(big.Int)
	b, err := n.Marshal()
	if err != nil {
		t.Fatalf("Marshalling failed: %s", err)
	}
	_, err = n.Unmarshal(b)
	if err != nil {
		t.Fatalf("UnMarshalling failed: %s", err)
	}
	n.PubKey.X = big.NewInt(3)
	_, err = n.Unmarshal(b)
	if err == nil {
		t.Fatal("UnMarshalling must fail for foreign signer")
	}
}

func Test_ClearSignature(t *testing.T) {
	p := new(eccutil.Point)
	p.X, p.Y = new(big.Int), new(big.Int)
	n := NewClearSignature(p)
	n.R.X, n.R.Y = new(big.Int), new(big.Int)
	n.SB.X, n.SB.Y = new(big.Int), new(big.Int)
	b, err := n.Marshal()
	if err != nil {
		t.Fatalf("Marshalling failed: %s", err)
	}
	_, err = n.Unmarshal(b)
	if err != nil {
		t.Fatalf("UnMarshalling failed: %s", err)
	}
	n.PubKey.X = big.NewInt(3)
	_, err = n.Unmarshal(b)
	if err == nil {
		t.Fatal("UnMarshalling must fail for foreign signer")
	}
}

func Test_BlindingParamServer(t *testing.T) {
	p := new(eccutil.Point)
	p.X, p.Y = new(big.Int), new(big.Int)
	n := NewBlindingParamServer(p)
	b, err := n.Marshal()
	if err != nil {
		t.Fatalf("Marshalling failed: %s", err)
	}
	_, err = n.Unmarshal(b)
	if err != nil {
		t.Fatalf("UnMarshalling failed: %s", err)
	}
	n.PubKey.X = big.NewInt(3)
	_, err = n.Unmarshal(b)
	if err == nil {
		t.Fatal("UnMarshalling must fail for foreign signer")
	}
}
