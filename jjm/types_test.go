package jjm

import (
	"github.com/ronperry/cryptoedge/eccutil"
	"encoding/hex"
	"math/big"
	"testing"
)

func Test_BlindingParamClient(t *testing.T) {
	p := new(eccutil.Point)
	p.X, p.Y = new(big.Int), new(big.Int)
	n := NewBlindingParamClient(p) //, PointRs1, PointRs2, ScalarLs1, ScalarLs2)
	n.PointRs1, n.PointRs2 = *eccutil.ZeroPoint(), *eccutil.ZeroPoint()
	n.ScalarLs1, n.ScalarLs2 = new(big.Int), new(big.Int)

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
	n.ScalarKs1, n.ScalarKs2 = new(big.Int), new(big.Int)
	n.PointRs1, n.PointRs2 = *eccutil.ZeroPoint(), *eccutil.ZeroPoint()
	n.ScalarLs1, n.ScalarLs2 = new(big.Int), new(big.Int)
	n.ScalarRs1, n.ScalarRs2 = new(big.Int), new(big.Int)
	n.IsUsed = false
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

	n.ScalarW, n.ScalarZ, n.ScalarE, n.ScalarD, n.ScalarA = new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	n.ScalarB, n.ScalarR1, n.ScalarR2, n.ScalarRs1, n.ScalarRs2 = new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	n.PointR1, n.PointR2 = *eccutil.ZeroPoint(), *eccutil.ZeroPoint()
	n.IsUsed = false

	b, err := n.Marshal()
	if err != nil {
		t.Fatalf("Marshalling failed: %s", err)
	}
	_, err = n.Unmarshal(b)
	if err != nil {
		t.Fatalf("UnMarshalling failed: %s", err)
	}
}

func Test_BlindMessage(t *testing.T) {
	p := new(eccutil.Point)
	p.X, p.Y = new(big.Int), new(big.Int)
	n := NewBlindMessage(p)
	n.M1, n.M2 = new(big.Int), new(big.Int)
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

	n.ScalarS1, n.ScalarS2 = new(big.Int), new(big.Int)
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
	n.PointR = *eccutil.ZeroPoint()
	n.ScalarS, n.ScalarR = new(big.Int), new(big.Int)
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
