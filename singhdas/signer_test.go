package singhdas

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ronperry/cryptoedge/eccutil"
	"testing"
)

func TestNewSigner(t *testing.T) {
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	privKey, pubKey, err := c.GenerateKey() // Signer long-term key
	if err != nil {
		t.Fatalf("Long term key gen failed: %s", err)
	}
	sig := NewSigner(privKey, pubKey, c)
	_ = sig
}

func TestNewRequest(t *testing.T) {
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	privKey, pubKey, err := c.GenerateKey() // Signer long-term key
	if err != nil {
		t.Fatalf("Long term key gen failed: %s", err)
	}
	sig := NewSigner(privKey, pubKey, c)
	sp, err := sig.NewRequest()
	if err != nil {
		t.Errorf("Cannot create request parameters: %s", err)
	}
	_ = sp
}

func TestSign(t *testing.T) {
	msg := []byte("Something to sign")
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	privKey, pubKey, err := c.GenerateKey() // Signer long-term key
	if err != nil {
		t.Fatalf("Long term key gen failed: %s", err)
	}
	sig := NewSigner(privKey, pubKey, c)
	sp, err := sig.NewRequest()
	if err != nil {
		t.Errorf("Cannot create request parameters: %s", err)
	}
	sc := NewSignerClient(pubKey, c)
	blindmsg, blindfac, err := sc.Blind(msg, sp.Q)
	if err != nil {
		t.Errorf("Cannot blind: %s", err)
	}
	blindsig, err := sig.Sign(blindmsg, sp)
	if err != nil {
		t.Errorf("Cannot sign: %s", err)
	}
	_, _ = blindsig, blindfac
}
