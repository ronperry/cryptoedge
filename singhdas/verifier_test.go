package singhdas

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ronperry/cryptoedge/eccutil"
	"math/big"
	"testing"
)

func TestVerify(t *testing.T) {
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
	unblindsig, err := sc.UnBlind(blindsig, blindfac)
	if err != nil {
		t.Errorf("Cannot unblind: %s", err)
	}
	ok, err := sc.Verify(msg, unblindsig)
	if err != nil {
		t.Errorf("Cannot unblind: %s", err)
	}
	if !ok {
		t.Error("Does not verify")
	}
	msg2 := []byte("Message that must fail")
	Hm := c.GenHash(msg2)
	ok, _ = sc.Verify(msg2, unblindsig)
	if ok {
		t.Error("Verify must fail")
	}
	badsig1 := new(SignatureInt)
	badsig1.Hm = Hm
	badsig1.R = unblindsig.R
	badsig1.S = unblindsig.S
	badsig1.r2 = unblindsig.r2
	ok, _ = sc.Verify(msg2, badsig1)
	if ok {
		t.Error("Verify must fail")
	}
	badsig2 := new(SignatureInt)
	badsig2.Hm = unblindsig.Hm
	badsig2.R = unblindsig.R
	badsig2.S = unblindsig.S
	badsig2.r2 = new(big.Int)
	badsig2.r2 = badsig2.r2.Sub(unblindsig.r2, big.NewInt(1))
	ok, _ = sc.Verify(msg, badsig2)
	if ok {
		t.Error("Verify must fail")
	}
	badsig3 := new(SignatureInt)
	badsig3.Hm = unblindsig.Hm
	badsig3.R = unblindsig.R
	badsig3.S = new(big.Int)
	badsig3.S = badsig3.S.Sub(unblindsig.S, big.NewInt(1))
	badsig3.r2 = unblindsig.r2
	ok, _ = sc.Verify(msg, badsig3)
	if ok {
		t.Error("Verify must fail")
	}
	badsig4 := new(SignatureInt)
	badsig4.Hm = unblindsig.Hm
	badsig4.R = new(eccutil.Point)
	badsig4.R.Y = unblindsig.R.Y
	badsig4.R.X = new(big.Int)
	badsig4.R.X = badsig4.R.X.Sub(unblindsig.R.X, big.NewInt(1))
	badsig4.S = unblindsig.S
	badsig4.r2 = unblindsig.r2
	ok, _ = sc.Verify(msg, badsig4)
	if ok {
		t.Error("Verify must fail")
	}

	_, _ = Hm, unblindsig
}
