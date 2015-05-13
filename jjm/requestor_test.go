package jjm

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ronperry/cryptoedge/eccutil"
	"testing"
)

func TestCalculateBlindingParams(t *testing.T) {
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
	_, _ = privateBlindingParams, privateSigParams
}

func TestBlind(t *testing.T) {
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
	_, _ = blindmessage, privateSigParams
}

func TestUnBlind(t *testing.T) {
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
	_ = signature
}
