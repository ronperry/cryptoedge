// Package singhdas implementes "A Novel Proficient Blind Signature Scheme using ECC" by Nitu Singh and Sumanjit Das
// Some of the tests/verifications are not necessary but done anyways.
package singhdas

import (
	"github.com/ronperry/cryptoedge/eccutil"
	"math/big"
)

// SignerClient encapsulates a client to a signer
type SignerClient struct {
	pubkey *eccutil.Point
	curve  *eccutil.Curve
}

// BlindingFactorsInt holds parameters required for unblinding
type BlindingFactorsInt struct {
	r2          *big.Int
	r1inv       *big.Int
	r1          *big.Int
	N           *big.Int
	Hm          *big.Int
	R           *eccutil.Point
	SignerBlind *eccutil.Point
	used        bool
}

// BlindMessageInt encapsulates a blinded message
type BlindMessageInt struct {
	Message     *big.Int
	SignerBlind *eccutil.Point
}

// SignatureInt is a plain signature
type SignatureInt struct {
	S  *big.Int
	r2 *big.Int
	R  *eccutil.Point
	Hm *big.Int
}

// NewSignerClient returns a new client to a signer over curve with publickey
func NewSignerClient(pubkey *eccutil.Point, curve *eccutil.Curve) *SignerClient {
	sc := new(SignerClient)
	sc.pubkey = pubkey
	sc.curve = curve
	return sc
}

// Blind blinds a message msg for signerBlind and returns the blinded message and the blinding factors
func (client SignerClient) Blind(message []byte, signerBlind *eccutil.Point) (blindMessage *BlindMessageInt, blindingFactors *BlindingFactorsInt, err error) {
	var loopcount int
	var M, N, r2 *big.Int
	var R *eccutil.Point
	r1, err := client.curve.ExtractR(signerBlind)
	if err != nil {
		return nil, nil, eccutil.ErrBadBlindParam
	}
	if !client.curve.WithinRange(r1) {
		return nil, nil, eccutil.ErrBadBlindParam
	}
	for {
		if loopcount > eccutil.MaxLoopCount {
			return nil, nil, eccutil.ErrMaxLoop
		}
		loopcount++
		M, err = client.curve.RandomElement()
		if err != nil {
			continue
		}
		N, err = client.curve.RandomElement()
		if err != nil {
			continue
		}
		MQ := client.curve.ScalarMult(signerBlind, M.Bytes())
		NG := client.curve.ScalarBaseMult(N.Bytes())
		R = client.curve.AddPoints(MQ, NG)
		r2, err = client.curve.ExtractR(R)
		if err != nil {
			continue
		}
		if !client.curve.WithinRange(r2) {
			continue
		}
		_, err = client.curve.TestParams(M, N, R.X, R.Y, r1)
		if err != nil {
			return nil, nil, eccutil.ErrBadBlindParam
		}
		break
	}
	r2inv, err := client.curve.ModInverse(r2)
	if err != nil {
		return nil, nil, eccutil.ErrBadBlindParam // should always be caught before
	}
	r1inv, err := client.curve.ModInverse(r1)
	if err != nil {
		return nil, nil, eccutil.ErrBadBlindParam // should always be caught before
	}
	Hm := client.curve.GenHash(message)
	ms := client.curve.Mod(eccutil.ManyMult(M, Hm, r1, r2inv))

	bf := new(BlindingFactorsInt)
	bf.r2 = r2
	bf.r1inv = r1inv
	bf.r1 = r1
	bf.N = N
	bf.Hm = Hm
	bf.R = R
	bf.SignerBlind = signerBlind

	bm := new(BlindMessageInt)
	bm.Message = ms
	bm.SignerBlind = signerBlind

	return bm, bf, nil
}

// UnBlind a signature using blinding factor
func (client SignerClient) UnBlind(blindSignature *BlindSignatureInt, blindingFactors *BlindingFactorsInt) (*SignatureInt, error) {
	if !client.curve.WithinRange(blindSignature.S) {
		return nil, eccutil.ErrBadBlindParam
	}
	if !client.curve.WithinRange(blindingFactors.r1) {
		return nil, eccutil.ErrBadBlindParam
	}
	if blindingFactors.used {
		return nil, eccutil.ErrParamReuse
	}
	NHm := eccutil.ManyMult(blindingFactors.N, blindingFactors.Hm)
	Sr2r1inv := eccutil.ManyMult(blindSignature.S, blindingFactors.r2, blindingFactors.r1inv)
	St := eccutil.ManyAdd(Sr2r1inv, NHm)
	S := client.curve.Mod(St)
	sig := new(SignatureInt)
	sig.S = S
	sig.r2 = blindingFactors.r2
	sig.R = blindingFactors.R
	sig.Hm = blindingFactors.Hm
	return sig, nil
}
