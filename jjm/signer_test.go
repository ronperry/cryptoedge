package jjm

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ronperry/cryptoedge/eccutil"
	"testing"
)

func TestNewSigner(t *testing.T) {
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	privkey, pubkey, err := c.GenerateKey()
	if err != nil {
		t.Fatalf("Error creating keys: %s", err)
	}
	signer := NewSigner(privkey, pubkey, c)
	_ = signer
}

func TestNewSignRequest(t *testing.T) {
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	privkey, pubkey, err := c.GenerateKey()
	if err != nil {
		t.Fatalf("Error creating keys: %s", err)
	}
	signer := NewSigner(privkey, pubkey, c)
	public, private, err := signer.NewSignRequest()
	if err != nil {
		t.Errorf("Error occured throughout parameter creation: %s", err)
	}
	_, _ = public, private
}

func TestSign(t *testing.T) {
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
	_ = blindsig
}
