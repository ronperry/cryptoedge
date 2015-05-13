package singhdas

import (
	"github.com/ronperry/cryptoedge/eccutil"
	"math/big"
)

// Signer is a signer instance
type Signer struct {
	privkey *big.Int
	pubkey  *eccutil.Point
	curve   *eccutil.Curve
}

// SignParamsInt encapsulates a single signature temporary key
type SignParamsInt struct {
	k    *big.Int       // Private, never share
	Q    *eccutil.Point // Public, given to requestor
	r    *big.Int
	used bool // Never use twice
}

// BlindSignatureInt represents a single blind signature
type BlindSignatureInt struct {
	SignerBlind *eccutil.Point
	S           *big.Int
}

// NewSigner returns a new signer
func NewSigner(privkey []byte, pubkey *eccutil.Point, curve *eccutil.Curve) *Signer {
	s := new(Signer)
	s.privkey = new(big.Int)
	s.privkey = s.privkey.SetBytes(privkey)
	s.pubkey = pubkey
	s.curve = curve
	return s
}

// NewRequest issues a new request keypair
func (signer Signer) NewRequest() (signparams *SignParamsInt, err error) {
	var loopcount int
	for {
		if loopcount > eccutil.MaxLoopCount {
			return nil, eccutil.ErrMaxLoop
		}
		loopcount++
		Kt, Qt, err := signer.curve.GenerateKey()
		if err != nil {
			continue
		}
		r, err := signer.curve.ExtractR(Qt)
		if err != nil {
			continue
		}
		if !signer.curve.WithinRange(r) {
			continue
		}
		sp := new(SignParamsInt)
		sp.k = eccutil.BytesToInt(Kt)
		sp.Q = Qt
		sp.r = r
		sp.used = false
		return sp, nil
	}
}

// Sign signs a blinded message
func (signer Signer) Sign(blindMessage *BlindMessageInt, signParams *SignParamsInt) (S *BlindSignatureInt, err error) {
	//signer.privkey * signParams.r + signParams.k * blindMessage.Message mod p
	if signParams.used {
		return nil, eccutil.ErrParamReuse
	}
	_, err = signer.curve.TestParams(blindMessage.Message, signer.privkey, signParams.r, signParams.k)
	if err != nil {
		return nil, eccutil.ErrBadBlindParam
	}

	Ar1 := eccutil.ManyMult(signer.privkey, signParams.r)
	Km := eccutil.ManyMult(signParams.k, blindMessage.Message)
	St := eccutil.ManyAdd(Ar1, Km)
	Sm := signer.curve.Mod(St)
	signParams.used = true
	S = new(BlindSignatureInt)
	S.S = Sm
	S.SignerBlind = blindMessage.SignerBlind
	return S, nil
}
