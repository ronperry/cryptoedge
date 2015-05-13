package singhdas

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
	n.Q = *eccutil.ZeroPoint()

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
	n.Q = *eccutil.ZeroPoint()
	n.K, n.R = new(big.Int), new(big.Int)
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

	n.R2, n.R1inv, n.R1, n.N, n.Hm = new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	n.SignerBlind, n.R = *eccutil.ZeroPoint(), *eccutil.ZeroPoint()

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
	n.Message = new(big.Int)
	n.SignerBlind = *eccutil.ZeroPoint()
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
	n.S = new(big.Int)
	n.SignerBlind = *eccutil.ZeroPoint()

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
	n.R = *eccutil.ZeroPoint()
	n.S, n.R2, n.Hm = new(big.Int), new(big.Int), new(big.Int)
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
