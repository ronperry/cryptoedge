package singhdas

import (
	"github.com/ronperry/cryptoedge/eccutil"
	"github.com/ronperry/cryptoedge/genericblinding"
	"math/big"
)

// GenericSigner is a generic interface signer instance
type GenericSigner struct {
	Signer
}

// NewGenericBlindingServer returns a new signer
func NewGenericBlindingServer(privkey []byte, pubkey *eccutil.Point, curve *eccutil.Curve) *GenericSigner {
	s := new(GenericSigner)
	s.privkey = new(big.Int)
	s.privkey = s.privkey.SetBytes(privkey)
	s.pubkey = pubkey
	s.curve = curve
	return s
}

// GenericSignerClient encapsulates a client to a signer using generic interface
type GenericSignerClient struct {
	SignerClient
}

// NewGenericBlindingClient returns a new client to a signer over curve with publickey
func NewGenericBlindingClient(pubkey *eccutil.Point, curve *eccutil.Curve) *GenericSignerClient {
	sc := new(GenericSignerClient)
	sc.pubkey = pubkey
	sc.curve = curve
	return sc
}

// Blind a ClearMessage with server-supplied BlindingParamClient
func (client GenericSignerClient) Blind(bpci genericblinding.BlindingParamClient, cmi genericblinding.ClearMessage) (genericblinding.BlindingFactors, genericblinding.BlindMessage, error) {
	_, err := genericblinding.MatchMessage(bpci, SchemeName, genericblinding.TypeBlindingParamClient, client.pubkey)
	if err != nil {
		return nil, nil, err
	}
	bpc, ok := bpci.(BlindingParamClient)
	if !ok {
		return nil, nil, genericblinding.ErrBadType
	}
	_, err = genericblinding.MatchMessage(cmi, SchemeName, genericblinding.TypeClearMessage, client.pubkey)
	if err != nil {
		return nil, nil, err
	}
	cm, ok := cmi.(ClearMessage)
	if !ok {
		return nil, nil, genericblinding.ErrBadType
	}

	bc := new(SignerClient)
	bc.pubkey = client.pubkey
	bc.curve = client.curve
	bm, bfac, err := bc.Blind(cm.UniqueID(), &bpc.Q)
	if err != nil {
		return nil, nil, err
	}
	_, _ = bm, bfac
	blindmessage := NewBlindMessage(client.pubkey)
	blindmessage.Message = bm.Message
	blindmessage.SignerBlind = *bm.SignerBlind

	blindingfactors := NewBlindingFactors(client.pubkey)

	blindingfactors.R2 = bfac.r2
	blindingfactors.R1inv = bfac.r1inv
	blindingfactors.R1 = bfac.r1
	blindingfactors.N = bfac.N
	blindingfactors.Hm = bfac.Hm
	blindingfactors.R = *bfac.R
	blindingfactors.SignerBlind = *bfac.SignerBlind
	blindingfactors.IsUsed = false

	return blindingfactors, blindmessage, nil

}

// Unblind a BlindSignature of ClearMessage using BlindingFactors
func (client GenericSignerClient) Unblind(bfaci genericblinding.BlindingFactors, cmi genericblinding.ClearMessage, bsigi genericblinding.BlindSignature) (genericblinding.ClearSignature, genericblinding.ClearMessage, error) {
	_, err := genericblinding.MatchMessage(bfaci, SchemeName, genericblinding.TypeBlindingFactors, client.pubkey)
	if err != nil {
		return nil, nil, err
	}
	bfac, ok := bfaci.(BlindingFactors)
	if !ok {
		return nil, nil, genericblinding.ErrBadType
	}

	_, err = genericblinding.MatchMessage(cmi, SchemeName, genericblinding.TypeClearMessage, client.pubkey)
	if err != nil {
		return nil, nil, err
	}
	cm, ok := cmi.(ClearMessage)
	if !ok {
		return nil, nil, genericblinding.ErrBadType
	}

	_, err = genericblinding.MatchMessage(bsigi, SchemeName, genericblinding.TypeBlindSignature, client.pubkey)
	if err != nil {
		return nil, nil, err
	}
	bsig, ok := bsigi.(BlindSignature)
	if !ok {
		return nil, nil, genericblinding.ErrBadType
	}

	bc := new(SignerClient)
	bc.pubkey = client.pubkey
	bc.curve = client.curve
	blindSignature := new(BlindSignatureInt)
	blindSignature.S = bsig.S
	blindSignature.SignerBlind = &bsig.SignerBlind

	blindingFactors := new(BlindingFactorsInt)
	blindingFactors.r2 = bfac.R2
	blindingFactors.r1inv = bfac.R1inv
	blindingFactors.r1 = bfac.R1
	blindingFactors.N = bfac.N
	blindingFactors.Hm = bfac.Hm
	blindingFactors.R = &bfac.R
	blindingFactors.SignerBlind = &bfac.SignerBlind
	blindingFactors.used = bfac.IsUsed

	signature, err := bc.UnBlind(blindSignature, blindingFactors)
	if err != nil {
		return nil, nil, err
	}
	csig := NewClearSignature(client.pubkey)
	csig.S = signature.S
	csig.R2 = signature.r2
	csig.R = *signature.R
	csig.Hm = signature.Hm

	return csig, cm, nil

}

// Verify that ClearSignature is a signature of ClearMessage
func (client GenericSignerClient) Verify(sigi genericblinding.ClearSignature, cmi genericblinding.ClearMessage) (bool, error) {
	_, err := genericblinding.MatchMessage(sigi, SchemeName, genericblinding.TypeClearSignature, client.pubkey)
	if err != nil {
		return false, err
	}
	sig, ok := sigi.(ClearSignature)
	if !ok {
		return false, genericblinding.ErrBadType
	}

	_, err = genericblinding.MatchMessage(cmi, SchemeName, genericblinding.TypeClearMessage, client.pubkey)
	if err != nil {
		return false, err
	}
	cm, ok := cmi.(ClearMessage)
	if !ok {
		return false, genericblinding.ErrBadType
	}

	bc := new(SignerClient)
	bc.pubkey = client.pubkey
	bc.curve = client.curve
	signature := new(SignatureInt)
	signature.S = sig.S
	signature.r2 = sig.R2
	signature.R = &sig.R
	signature.Hm = sig.Hm
	return bc.Verify(cm.UniqueID(), signature)

}

// GetParams generates one-time BlindingParam
func (server GenericSigner) GetParams() (genericblinding.BlindingParamClient, genericblinding.BlindingParamServer, error) {
	bs := new(Signer)
	bs.curve = server.curve
	bs.pubkey = server.pubkey
	bs.privkey = server.privkey
	signparams, err := bs.NewRequest()
	if err != nil {
		return nil, nil, err
	}
	clientparams := NewBlindingParamClient(server.pubkey)
	clientparams.Q = *signparams.Q
	serverparams := NewBlindingParamServer(server.pubkey)
	serverparams.K = signparams.k
	serverparams.Q = *signparams.Q
	serverparams.R = signparams.r
	serverparams.IsUsed = false

	//return clientparams.(genericblinding.BlindingParamClient), serverparams.(genericblinding.BlindingParamServer), nil
	return clientparams, serverparams, nil
}

// Sign a BlindMessage usign BlindingParam
func (server GenericSigner) Sign(bpsi genericblinding.BlindingParamServer, bmi genericblinding.BlindMessage) (genericblinding.BlindSignature, error) {
	_, err := genericblinding.MatchMessage(bpsi, SchemeName, genericblinding.TypeBlindingParamServer, server.pubkey)
	if err != nil {
		return nil, err
	}
	bps, ok := bpsi.(BlindingParamServer)
	if !ok {
		return nil, genericblinding.ErrBadType
	}

	_, err = genericblinding.MatchMessage(bmi, SchemeName, genericblinding.TypeBlindMessage, server.pubkey)
	if err != nil {
		return nil, err
	}
	bm, ok := bmi.(BlindMessage)
	if !ok {
		return nil, genericblinding.ErrBadType
	}

	bs := new(Signer)
	bs.curve = server.curve
	bs.pubkey = server.pubkey
	bs.privkey = server.privkey
	blindMessage := new(BlindMessageInt)
	blindMessage.Message = bm.Message
	blindMessage.SignerBlind = &bm.SignerBlind
	signParams := new(SignParamsInt)
	signParams.Q = &bps.Q
	signParams.k = bps.K
	signParams.r = bps.R
	signParams.used = bps.IsUsed
	S, err := bs.Sign(blindMessage, signParams)
	if err != nil {
		return nil, err
	}
	signature := NewBlindSignature(server.pubkey)
	signature.SignerBlind = *S.SignerBlind
	signature.S = S.S

	return signature, nil

}
