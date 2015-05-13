// Package jcc implements "An ECC-Based Blind Signature Scheme" by Fuh-Gwo Jeng, Tzer-Long Chen and Tzer-Shyong Chen
// A lot of the sanity checks performed by the code make no mathematical sense since they are impossible to produce if the code is actually bug-less
// Under certain conditions both msg and the image of the msg have valid signatures (implausible)
//
// Generate key:
// 		Private key == blinding factor (ni)
// Blind:
// 		blind message = scalarmult(message,scalarmult(blinding factor, PublicKey)) (POINT)
// Sign:
// 		r = nv x blind message (POINT); s = (nv+ns) x blind message (POINT)
// 		ns is the privat key of the signer
//		record nv,blind message. protect priv-key of signer
// Unblind:
// 		s' = s - m x ni x Ps   (Ps public key signer) (POINT)
// 		m' = ni(ni-1)m
// Verify:
//		r == s' - m' x Ps
//
// Public data:
//		Signer: Public Key. Private key and token remain secret
//		Client:
// 			Blind() output: bmsg is public and sent to Signer. bfac is secret, needed for unblinding
//				bfac should be destroyed after unblind (and verification)
// 			Blind() input  msg must be retained until unblinding and destroyed after
// 		Signature (r, sb, mb):
//			From signer -> r
//			From client -> Output of Unblind(): sb, mb
//		Verification operates on: Signer public key, Signature(r, sb, mb)
//
// For more information: http://ojs.academypublisher.com/index.php/jnw/article/viewFile/0508921928/2053
//
package jcc

import (
	"github.com/ronperry/cryptoedge/eccutil"
	"math/big"
)

// MaxLoopCount is the maximum number of tries we do for parameter search
const MaxLoopCount = 1000

// Refactor begin

// BlindingClient a blinding client
type BlindingClient struct {
	curve  *eccutil.Curve
	PubKey *eccutil.Point
}

// NewBlindingClient returns a new BlindingClient
func NewBlindingClient(curve *eccutil.Curve, pubKey *eccutil.Point) *BlindingClient {
	bc := new(BlindingClient)
	bc.curve = curve
	bc.PubKey = pubKey
	return bc
}

// Blind returns a blinded message and the blinding factor. bmsg is sent to signer (public), bfac is private and needed for unblinding
func (client BlindingClient) Blind(msg []byte) (bmsg *eccutil.Point, bfac []byte, err error) {
	// blind message = scalarmult(message,scalarmult(blinding factor, scalarmult(blindingfactor,basepoint)) (POINT)
	var loopcount int
	if len(msg) < 10 {
		return nil, nil, eccutil.ErrMsgShort
	}
	t := new(big.Int)
	t.SetBytes(msg)
	_, err = client.curve.TestCoordinate(t)
	if err != nil {
		return nil, nil, err
	}
	//cparams := client.curve.Params()
	for {
		if loopcount > MaxLoopCount {
			return nil, nil, eccutil.ErrMaxLoop
		}
		loopcount++
		bfact, bpoint, err := client.curve.GenerateKey()
		if err != nil {
			return nil, nil, err
		}
		bfac2 := client.curve.ScalarMult(bpoint, bfact)
		_, err = client.curve.TestPoint(bpoint.X, bpoint.Y, bfac2.X, bfac2.Y) // This cannot really happen
		if err != nil {
			return nil, nil, err
		}
		_, err = client.curve.TestPoint(bfac2.X, bfac2.Y, client.curve.Params.Gx, client.curve.Params.Gy)
		if err != nil {
			continue
		}
		bmsgt := client.curve.ScalarMult(bfac2, msg)
		_, err = client.curve.TestPoint(bpoint.X, bpoint.Y, bmsgt.X, bmsgt.Y)
		if err != nil {
			continue
		}
		_, err = client.curve.TestPoint(bfac2.X, bfac2.Y, bmsgt.X, bmsgt.Y) // This cannot really happen
		if err != nil {
			return nil, nil, err
		}
		_, err = client.curve.TestPoint(bmsgt.X, bmsgt.Y, client.curve.Params.Gx, client.curve.Params.Gy)
		if err != nil {
			continue
		}
		return bmsgt, bfact, nil
	}
}

// Unblind unblinds a signature. sb and mb are required for verification
func (client BlindingClient) Unblind(bfac, msg []byte, s *eccutil.Point) (sb *eccutil.Point, mb []byte) {
	ni := new(big.Int)
	m := new(big.Int)
	mbt := new(big.Int)
	nim := new(big.Int)

	// Calculate m' = ni(ni-1)*m
	ni.SetBytes(bfac)
	m.SetBytes(msg)
	nim = nim.Mul(ni, nim.Sub(ni, big.NewInt(1))) // ni(ni-1)
	mbt = mbt.Mul(nim, m)                         // (ni(ni-1))*m
	mbt = eccutil.ManyMult(ni, nim.Sub(ni, big.NewInt(1)), m)
	mbx := mbt.Bytes()

	// Calculate: s' = s - m x ni x Ps   (Ps public key signer) (POINT)
	nit := client.curve.ScalarMult(client.PubKey, bfac) // ni x Ps
	mt := client.curve.ScalarMult(nit, msg)             // m x (ni x Ps)
	// inverse mt to make substraction
	mt.Y = mt.Y.Neg(mt.Y)
	st := client.curve.AddPoints(s, mt) // s - (m x ni x Ps)
	return st, mbx
}

// Verify a signature
func (client BlindingClient) Verify(r, sb *eccutil.Point, mb []byte) bool {
	//		r == s' - m' x Ps
	c := client.curve.ScalarMult(client.PubKey, mb) // m' x Ps
	c.Y = c.Y.Neg(c.Y)                              // neg m'
	cv := client.curve.AddPoints(sb, c)             // s + neg (m x Ps)
	if r.X.Cmp(cv.X) == 0 && r.Y.Cmp(cv.Y) == 0 {   // r == s + neg (m x Ps) ?
		return true
	}
	return false
}
