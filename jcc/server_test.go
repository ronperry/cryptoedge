package jcc

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ronperry/cryptoedge/eccutil"
	"testing"
)

func TestNewSigner(t *testing.T) {
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	sigpriv, sigpub, _ := c.GenerateKey()
	signer := NewBlindingServer(sigpriv, sigpub, c, Fakeunique)
	_ = signer
}

func TestSigner_Sign(t *testing.T) {
	msg := []byte("Random message without meaning, should be unique")
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	sigpriv, sigpub, _ := c.GenerateKey()
	signer := NewBlindingServer(sigpriv, sigpub, c, Fakeunique)
	bc := NewBlindingClient(c, sigpub)

	bmsg, bfac, err := bc.Blind(msg)
	if err != nil {
		t.Errorf("Blinding failed: %s", err)
	}

	r, s, err := signer.Sign(bmsg)
	if err != nil {
		t.Errorf("Signature failed")
	}
	_, _, _ = r, s, bfac
}
