package jjm

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ronperry/cryptoedge/eccutil"
	"testing"
)

func Test_GenericRequest(t *testing.T) {
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	privkey, pubkey, err := c.GenerateKey()
	if err != nil {
		t.Fatalf("Error creating keys: %s", err)
	}
	signer := NewGenericBlindingServer(privkey, pubkey, c)
	clientParams, serverParams, err := signer.GetParams()
	if err != nil {
		t.Errorf("Error occured throughout parameter creation: %s", err)
	}
	_, _ = clientParams, serverParams
}

func Test_GenericBlind(t *testing.T) {
	msg := []byte("Message to be blinded")
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	privkey, pubkey, err := c.GenerateKey()
	if err != nil {
		t.Fatalf("Error creating keys: %s", err)
	}
	signer := NewGenericBlindingServer(privkey, pubkey, c)
	client := NewGenericBlindingClient(pubkey, c)

	clientParams, serverParams, err := signer.GetParams()
	if err != nil {
		t.Errorf("Error occured throughout parameter creation: %s", err)
	}
	cm := NewClearMessage(msg)
	clientFactors, blindMessage, err := client.Blind(clientParams, cm)
	if err != nil {
		t.Errorf("Error occured throughout blinding: %s", err)
	}
	_, _, _, _, _ = clientParams, serverParams, client, clientFactors, blindMessage
}

func Test_GenericSign(t *testing.T) {
	msg := []byte("Message to be blinded")
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	privkey, pubkey, err := c.GenerateKey()
	if err != nil {
		t.Fatalf("Error creating keys: %s", err)
	}
	signer := NewGenericBlindingServer(privkey, pubkey, c)
	client := NewGenericBlindingClient(pubkey, c)

	clientParams, serverParams, err := signer.GetParams()
	if err != nil {
		t.Errorf("Error occured throughout parameter creation: %s", err)
	}
	cm := NewClearMessage(msg)
	clientFactors, blindMessage, err := client.Blind(clientParams, cm)
	if err != nil {
		t.Errorf("Error occured throughout blinding: %s", err)
	}
	blindsignature, err := signer.Sign(serverParams, blindMessage)
	if err != nil {
		t.Errorf("Error occured throughout signing: %s", err)
	}
	_, _, _, _, _ = clientParams, blindsignature, client, clientFactors, blindMessage
}

func Test_GenericUnBlind(t *testing.T) {
	msg := []byte("Message to be blinded")
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	privkey, pubkey, err := c.GenerateKey()
	if err != nil {
		t.Fatalf("Error creating keys: %s", err)
	}
	signer := NewGenericBlindingServer(privkey, pubkey, c)
	client := NewGenericBlindingClient(pubkey, c)

	clientParams, serverParams, err := signer.GetParams()
	if err != nil {
		t.Errorf("Error occured throughout parameter creation: %s", err)
	}
	cm := NewClearMessage(msg)
	clientFactors, blindMessage, err := client.Blind(clientParams, cm)
	if err != nil {
		t.Errorf("Error occured throughout blinding: %s", err)
	}
	blindsignature, err := signer.Sign(serverParams, blindMessage)
	if err != nil {
		t.Errorf("Error occured throughout signing: %s", err)
	}
	clearsig, clearmsg, err := client.Unblind(clientFactors, cm, blindsignature)
	if err != nil {
		t.Errorf("Error occured throughout unblinding: %s", err)
	}
	_, _, _, _, _ = clearsig, clearmsg, client, clientFactors, blindMessage
}

func Test_GenericVerify(t *testing.T) {
	msg := []byte("Message to be blinded")
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	privkey, pubkey, err := c.GenerateKey()
	if err != nil {
		t.Fatalf("Error creating keys: %s", err)
	}
	signer := NewGenericBlindingServer(privkey, pubkey, c)
	client := NewGenericBlindingClient(pubkey, c)

	clientParams, serverParams, err := signer.GetParams()
	if err != nil {
		t.Errorf("Error occured throughout parameter creation: %s", err)
	}
	cm := NewClearMessage(msg)
	clientFactors, blindMessage, err := client.Blind(clientParams, cm)
	if err != nil {
		t.Errorf("Error occured throughout blinding: %s", err)
	}
	blindsignature, err := signer.Sign(serverParams, blindMessage)
	if err != nil {
		t.Errorf("Error occured throughout signing: %s", err)
	}
	clearsig, clearmsg, err := client.Unblind(clientFactors, cm, blindsignature)
	if err != nil {
		t.Errorf("Error occured throughout unblinding: %s", err)
	}
	ok, err := client.Verify(clearsig, clearmsg)
	if err != nil {
		t.Errorf("Error occured throughout verify: %s", err)
	}
	if !ok {
		t.Error("Message does not verify")
	}
	_, _, _, _, _ = clearsig, clearmsg, client, clientFactors, blindMessage
}
