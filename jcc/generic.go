package jcc

//ToDo: Verify Scheme, PublicKey, DataType
//ToDo: Test for interface conversion errors

import (
	"github.com/ronperry/cryptoedge/eccutil"
	"github.com/ronperry/cryptoedge/genericblinding"
)

// GenericBlindingClient a blinding client using the generic interface
type GenericBlindingClient struct {
	BlindingClient
}

// GenericBlindingServer is holds a blinding server
type GenericBlindingServer struct {
	BlindingServer
}

// NewGenericBlindingClient returns a new GenericBlindingClient
func NewGenericBlindingClient(curve *eccutil.Curve, pubKey *eccutil.Point) *GenericBlindingClient {
	bc := new(GenericBlindingClient)
	bc.curve = curve
	bc.PubKey = pubKey
	return bc
}

// Blind returns a blinded message and the blinding factor. BlindingParamClient can be nil
func (client GenericBlindingClient) Blind(bpci genericblinding.BlindingParamClient, cmi genericblinding.ClearMessage) (genericblinding.BlindingFactors, genericblinding.BlindMessage, error) {
	//bpc := bpci.(BlindingParamClient) // Nil anyways
	_, err := genericblinding.MatchMessage(cmi, SchemeName, genericblinding.TypeClearMessage, client.PubKey)
	if err != nil {
		return nil, nil, err
	}
	cm, ok := cmi.(ClearMessage)
	if !ok {
		return nil, nil, genericblinding.ErrBadType
	}
	c := NewBlindingClient(client.curve, client.PubKey)
	bmt, bft, err := c.Blind(cm.UniqueID())
	if err != nil {
		return nil, nil, err
	}
	bf := NewBlindingFactors(client.PubKey)
	bm := NewBlindMessage(client.PubKey)
	bm.Message = *bmt
	bf.Factor = bft
	return bf, bm, nil
}

// Unblind unblinds a signature
func (client GenericBlindingClient) Unblind(bfi genericblinding.BlindingFactors, cmi genericblinding.ClearMessage, bsi genericblinding.BlindSignature) (genericblinding.ClearSignature, genericblinding.ClearMessage, error) {
	_, err := genericblinding.MatchMessage(bfi, SchemeName, genericblinding.TypeBlindingFactors, client.PubKey)
	if err != nil {
		return nil, nil, err
	}
	bf, ok := bfi.(BlindingFactors)
	if !ok {
		return nil, nil, genericblinding.ErrBadType
	}

	_, err = genericblinding.MatchMessage(cmi, SchemeName, genericblinding.TypeClearMessage, client.PubKey)
	if err != nil {
		return nil, nil, err
	}
	cm, ok := cmi.(ClearMessage)
	if !ok {
		return nil, nil, genericblinding.ErrBadType
	}

	_, err = genericblinding.MatchMessage(bsi, SchemeName, genericblinding.TypeBlindSignature, client.PubKey)
	if err != nil {
		return nil, nil, err
	}
	bs, ok := bsi.(BlindSignature)
	if !ok {
		return nil, nil, genericblinding.ErrBadType
	}

	c := NewBlindingClient(client.curve, client.PubKey)
	sb, mb := c.Unblind(bf.Factor, cm.UniqueID(), &bs.S)
	cmo := NewClearMessage(mb)
	csig := NewClearSignature(client.PubKey)
	csig.R = bs.R
	csig.SB = *sb
	return csig, cmo, nil
}

// Verify a signature
func (client GenericBlindingClient) Verify(csi genericblinding.ClearSignature, cmi genericblinding.ClearMessage) (bool, error) {
	_, err := genericblinding.MatchMessage(csi, SchemeName, genericblinding.TypeClearSignature, client.PubKey)
	if err != nil {
		return false, err
	}
	cs, ok := csi.(ClearSignature)
	if !ok {
		return false, genericblinding.ErrBadType
	}

	_, err = genericblinding.MatchMessage(cmi, SchemeName, genericblinding.TypeClearMessage, client.PubKey)
	if err != nil {
		return false, err
	}
	cm, ok := cmi.(ClearMessage)
	if !ok {
		return false, genericblinding.ErrBadType
	}
	c := NewBlindingClient(client.curve, client.PubKey)
	return c.Verify(&cs.R, &cs.SB, cm.Message), nil
}

// NewGenericBlindingServer creates a new BlindingServer
func NewGenericBlindingServer(privkey []byte, pubkey *eccutil.Point, curve *eccutil.Curve, uniqueTest func([32]byte) bool) *GenericBlindingServer {
	bs := new(GenericBlindingServer)
	bs.PubKey = pubkey
	bs.privKey = privkey
	bs.curve = curve
	bs.uniqueTest = uniqueTest
	return bs
}

// Sign a message. BlindingParamServer can be nil (not used in JCC)
func (server GenericBlindingServer) Sign(bpsi genericblinding.BlindingParamServer, bmi genericblinding.BlindMessage) (genericblinding.BlindSignature, error) {
	//bpsi is nil for this scheme, not tested
	_, err := genericblinding.MatchMessage(bmi, SchemeName, genericblinding.TypeBlindMessage, server.PubKey)
	if err != nil {
		return nil, err
	}
	bm, ok := bmi.(BlindMessage)
	if !ok {
		return nil, genericblinding.ErrBadType
	}

	bs := NewBlindingServer(server.privKey, server.PubKey, server.curve, server.uniqueTest)
	r, s, err := bs.Sign(&bm.Message)
	if err != nil {
		return nil, err
	}
	bsig := NewBlindSignature(server.PubKey)
	bsig.R = *r
	bsig.S = *s
	return bsig, nil
}

// GetParams returns signature request parameters. Unused in JCC
func (server GenericBlindingServer) GetParams() (genericblinding.BlindingParamClient, genericblinding.BlindingParamServer, error) {
	bpc := NewBlindingParamClient(server.PubKey)
	bps := NewBlindingParamServer(server.PubKey)
	return bpc, bps, nil
}
