package jcc

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ronperry/cryptoedge/eccutil"
	"testing"
)

func TestGenericVerify(t *testing.T) {
	msg := []byte("Random message without meaning, should be unique")
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	sigpriv, sigpub, err := c.GenerateKey()
	if err != nil {
		t.Errorf("Signer key gen failed: %s", err)
	}

	bc := NewGenericBlindingClient(c, sigpub)
	cm := NewClearMessage(msg)

	bfac, bmsg, err := bc.Blind(nil, cm)
	if err != nil {
		t.Errorf("Blinding failed: %s", err)
	}
	bs := NewGenericBlindingServer(sigpriv, sigpub, c, Fakeunique)

	bsig, err := bs.Sign(nil, bmsg)
	if err != nil {
		t.Errorf("Signature failed")
	}

	st, mt, _ := bc.Unblind(bfac, cm, bsig)

	ok, _ := bc.Verify(st, mt)
	if !ok {
		t.Errorf("Signature verification failed")
	}
}
