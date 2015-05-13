package jcc

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ronperry/cryptoedge/eccutil"
	"testing"
)

func TestSetCurve(t *testing.T) {
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	_ = c
	t.Skip()
}

func TestGenerateKey(t *testing.T) {
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	priv, pub, err := c.GenerateKey()
	if err != nil {
		t.Errorf("Generate key failed: %s", err)
	}
	_, _ = priv, pub
}

func TestBlind(t *testing.T) {
	msg := []byte("Random message without meaning, should be unique")
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	bc := NewBlindingClient(c, nil)
	bmsg, bfac, err := bc.Blind(msg)
	if err != nil {
		t.Errorf("Blinding failed: %s", err)
	}
	_, _ = bmsg, bfac
}

func TestSign(t *testing.T) {
	msg := []byte("Random message without meaning, should be unique")
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	sigpriv, sigpub, err := c.GenerateKey()
	if err != nil {
		t.Errorf("Signer key gen failed: %s", err)
	}

	bc := NewBlindingClient(c, sigpub)
	bmsg, bfac, err := bc.Blind(msg)
	if err != nil {
		t.Errorf("Blinding failed: %s", err)
	}

	bs := NewBlindingServer(sigpriv, sigpub, c, Fakeunique)

	r, s, err := bs.Sign(bmsg)
	if err != nil {
		t.Errorf("Signature failed")
	}
	_, _ = r, s
	_, _ = bmsg, bfac
}

func TestUnblind(t *testing.T) {
	msg := []byte("Random message without meaning, should be unique")
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	sigpriv, sigpub, err := c.GenerateKey()
	if err != nil {
		t.Errorf("Signer key gen failed: %s", err)
	}

	bc := NewBlindingClient(c, sigpub)
	bmsg, bfac, err := bc.Blind(msg)
	if err != nil {
		t.Errorf("Blinding failed: %s", err)
	}
	bs := NewBlindingServer(sigpriv, sigpub, c, Fakeunique)

	r, s, err := bs.Sign(bmsg)
	if err != nil {
		t.Errorf("Signature failed")
	}
	st, mt := bc.Unblind(bfac, msg, s)
	_, _, _ = st, mt, r
	_, _ = r, s
	_, _ = bmsg, bfac
}

func TestVerify(t *testing.T) {
	msg := []byte("Random message without meaning, should be unique")
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	sigpriv, sigpub, err := c.GenerateKey()
	if err != nil {
		t.Errorf("Signer key gen failed: %s", err)
	}

	bc := NewBlindingClient(c, sigpub)
	bmsg, bfac, err := bc.Blind(msg)
	if err != nil {
		t.Errorf("Blinding failed: %s", err)
	}
	bs := NewBlindingServer(sigpriv, sigpub, c, Fakeunique)

	r, s, err := bs.Sign(bmsg)
	if err != nil {
		t.Errorf("Signature failed")
	}
	st, mt := bc.Unblind(bfac, msg, s)
	ok := bc.Verify(r, st, mt)
	if !ok {
		t.Errorf("Signature verification failed")
	}
}

func Test_ProtocolVerifyOneMessage(t *testing.T) {
	msga := []byte("Random message without meaning, should be unique")
	// Setup
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	sigpriv, sigpub, err := c.GenerateKey()
	if err != nil {
		t.Errorf("Signer key gen failed: %s", err)
	}
	bc := NewBlindingClient(c, sigpub)
	bs := NewBlindingServer(sigpriv, sigpub, c, Fakeunique)

	// generate two signatures per message
	bmsga1, bfaca1, err := bc.Blind(msga)
	if err != nil {
		t.Errorf("Blinding failed: %s", err)
	}
	ra11, sa11, err := bs.Sign(bmsga1)
	if err != nil {
		t.Errorf("Signature failed")
	}
	ra12, sa12, err := bs.Sign(bmsga1)
	if err != nil {
		t.Errorf("Signature failed")
	}
	sta11, mta11 := bc.Unblind(bfaca1, msga, sa11)
	ok := bc.Verify(ra11, sta11, mta11)
	if !ok {
		t.Errorf("Signature verification failed")
	}
	sta12, mta12 := bc.Unblind(bfaca1, msga, sa12)
	ok = bc.Verify(ra12, sta12, mta12)
	if !ok {
		t.Errorf("Signature verification failed")
	}

	ok = bc.Verify(ra11, sta12, mta12)
	if ok {
		t.Errorf("Signature must fail on r-switch")
	}
	ok = bc.Verify(ra12, sta11, mta12)
	if ok {
		t.Errorf("Signature must fail on s-switch")
	}
	ok = bc.Verify(ra11, sta11, mta12)
	if !ok {
		t.Errorf("Signature must work on signature over same message")
	}
}

func Test_ProtocolVerifyTwoMessages(t *testing.T) {
	msga := []byte("Random message without meaning, should be unique")
	msgb := []byte("Another message without meaning, should be unique")
	// Setup
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	sigpriv, sigpub, err := c.GenerateKey()
	if err != nil {
		t.Errorf("Signer key gen failed: %s", err)
	}
	bc := NewBlindingClient(c, sigpub)
	bs := NewBlindingServer(sigpriv, sigpub, c, Fakeunique)

	// generate two signatures per message
	bmsga1, bfaca1, err := bc.Blind(msga)
	if err != nil {
		t.Errorf("Blinding failed: %s", err)
	}
	bmsgb1, bfacb1, err := bc.Blind(msgb)
	if err != nil {
		t.Errorf("Blinding failed: %s", err)
	}
	ra11, sa11, err := bs.Sign(bmsga1)
	if err != nil {
		t.Errorf("Signature failed")
	}
	rb11, sb11, err := bs.Sign(bmsgb1)
	if err != nil {
		t.Errorf("Signature failed")
	}
	sta11, mta11 := bc.Unblind(bfaca1, msga, sa11)
	ok := bc.Verify(ra11, sta11, mta11)
	if !ok {
		t.Errorf("Signature verification failed")
	}
	stb11, mtb11 := bc.Unblind(bfacb1, msgb, sb11)
	ok = bc.Verify(rb11, stb11, mtb11)
	if !ok {
		t.Errorf("Signature verification failed")
	}

	ok = bc.Verify(ra11, stb11, mta11)
	if ok {
		t.Errorf("Signature must fail on r-switch")
	}
	ok = bc.Verify(rb11, sta11, mta11)
	if ok {
		t.Errorf("Signature must fail on s-switch")
	}
	ok = bc.Verify(ra11, sta11, mtb11)
	if ok {
		t.Errorf("Signature must fail on different message")
	}
	_ = sb11
}
