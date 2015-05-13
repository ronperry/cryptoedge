package jjm

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ronperry/cryptoedge/eccutil"
	"math/big"
	"testing"
)

func TestVerify(t *testing.T) {
	msg := []byte("Message to be blind-signed")
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	privkey, pubkey, err := c.GenerateKey()
	if err != nil {
		t.Fatalf("Error creating keys: %s", err)
	}
	signer := NewSigner(privkey, pubkey, c)
	publicSigParams, privateSigParams, err := signer.NewSignRequest()
	if err != nil {
		t.Errorf("Error occured throughout parameter creation: %s", err)
	}
	bc := NewBlindingClient(c, pubkey)

	privateBlindingParams, err := bc.CalculateBlindingParams(publicSigParams)
	if err != nil {
		t.Errorf("CalculateBlindingParams failed: %s", err)
	}

	blindmessage, err := bc.Blind(msg, publicSigParams, privateBlindingParams)
	if err != nil {
		t.Errorf("Blind failed: %s", err)
	}

	blindsig, err := signer.Sign(blindmessage, privateSigParams)
	if err != nil {
		t.Errorf("Sign failed: %s", err)
	}
	signature, err := bc.Unblind(blindsig, privateBlindingParams)
	if err != nil {
		t.Errorf("Unblind failed: %s", err)
	}

	ok := bc.Verify(msg, signature)
	if !ok {
		t.Errorf("Verify failed")
	}
	badsig1 := new(SignatureInt)
	badsig1.PointR = signature.PointR
	badsig1.ScalarR = signature.ScalarR
	badsig1.ScalarS = new(big.Int)
	badsig1.ScalarS = badsig1.ScalarS.Sub(signature.ScalarS, big.NewInt(1))
	ok = bc.Verify(msg, badsig1)
	if ok {
		t.Errorf("Verify must fail")
	}
	badsig2 := new(SignatureInt)
	badsig2.PointR = signature.PointR
	badsig2.ScalarS = signature.ScalarS
	badsig2.ScalarR = new(big.Int)
	badsig2.ScalarR = badsig2.ScalarR.Sub(signature.ScalarR, big.NewInt(1))
	ok = bc.Verify(msg, badsig1)
	if ok {
		t.Errorf("Verify must fail")
	}
	badsig3 := new(SignatureInt)
	badsig3.PointR = new(eccutil.Point)
	badsig3.PointR.Y = signature.PointR.Y
	badsig3.PointR.X = new(big.Int)
	badsig3.PointR.X = badsig3.PointR.X.Sub(signature.PointR.X, big.NewInt(1))
	badsig3.ScalarS = signature.ScalarS
	badsig3.ScalarR = signature.ScalarR
	ok = bc.Verify(msg, badsig3)
	if ok {
		t.Errorf("Verify must fail")
	}

	msg2 := []byte("Another message that may not verify")
	ok = bc.Verify(msg2, signature)
	if ok {
		t.Errorf("Verify must fail")
	}

	_, pubkey2, err := c.GenerateKey()
	if err != nil {
		t.Fatalf("Error creating keys: %s", err)
	}
	bc2 := NewBlindingClient(c, pubkey2)
	ok = bc2.Verify(msg, signature)
	if ok {
		t.Errorf("Verify must fail")
	}
}
