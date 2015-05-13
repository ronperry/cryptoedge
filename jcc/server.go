package jcc

import (
	"crypto/sha256"
	"github.com/ronperry/cryptoedge/eccutil"
	"math/big"
)

// Convinience Signer abstraction

// BlindingServer is holds a blinding server
type BlindingServer struct {
	PubKey     *eccutil.Point
	privKey    []byte
	curve      *eccutil.Curve
	uniqueTest func([32]byte) bool
}

// Fakeunique is a test function for the uniqueness-test. Must be implemented for production use
func Fakeunique(x [32]byte) bool {
	return true
}

// NewBlindingServer creates a new BlindingServer
func NewBlindingServer(privkey []byte, pubkey *eccutil.Point, curve *eccutil.Curve, uniqueTest func([32]byte) bool) *BlindingServer {
	bs := new(BlindingServer)
	bs.PubKey = pubkey
	bs.privKey = privkey
	bs.curve = curve
	bs.uniqueTest = uniqueTest
	return bs
}

func (bs BlindingServer) uniqueToken(nv []byte, point *eccutil.Point) [32]byte {
	t := make([]byte, len(nv))
	copy(t, nv)
	t = append(t, point.X.Bytes()...)
	t = append(t, point.Y.Bytes()...)
	return sha256.Sum256(t)
}

// Sign a blind message, return signature. callback for checking bmsg -> nv uniqueness. r and s are returned to client. r is public for verification
func (bs BlindingServer) Sign(bmsg *eccutil.Point) (r, s *eccutil.Point, err error) {
	// 		r = nv x blind message (POINT);
	// 		s = (nv+ns) x blind message (POINT)
	// 		Test that nv produces point (not infinity etc)
	// 		ns is the privat key of the signer
	//		record nv,blind message. protect priv-key of signer
	// Generate nv and test if it does not produce infinity
	// testunique(hash(bmsg,nv))==true
	var loopcount int
	_, err = bs.curve.TestPoint(bmsg.X, bmsg.Y, bs.PubKey.X, bs.PubKey.Y) // reflection
	if err != nil {
		return nil, nil, err
	}
	_, err = bs.curve.TestPoint(bmsg.X, bmsg.Y, bs.curve.Params.Gx, bs.curve.Params.Gx) // reflection generator
	if err != nil {
		return nil, nil, err
	}
	for {
		if loopcount > MaxLoopCount {
			return nil, nil, eccutil.ErrMaxLoop
		}
		loopcount++
		nv, err := bs.curve.GenNV()
		if err != nil {
			return nil, nil, err
		}
		// Check for unique parameters
		if !bs.uniqueTest(bs.uniqueToken(nv, bmsg)) {
			continue
		}
		//rt := new(Point)
		rt := bs.curve.ScalarMult(bmsg, nv)
		_, err = bs.curve.TestPoint(rt.X, rt.Y, bs.PubKey.X, bs.PubKey.Y) // should never happen
		if err != nil {
			continue
		}
		_, err = bs.curve.TestPoint(rt.X, rt.Y, bs.curve.Params.Gx, bs.curve.Params.Gx) // should never happen
		if err != nil {
			continue
		}

		nvprivsum := new(big.Int)
		privi := new(big.Int)
		nvi := new(big.Int)
		nvi.SetBytes(nv)
		privi.SetBytes(bs.privKey)
		nvprivsum = nvprivsum.Add(nvi, privi)
		st := bs.curve.ScalarMult(bmsg, nvprivsum.Bytes())
		_, err = bs.curve.TestPoint(st.X, st.Y, bs.PubKey.X, bs.PubKey.Y) // should never happen
		if err != nil {
			continue
		}
		_, err = bs.curve.TestPoint(st.X, st.Y, bs.curve.Params.Gx, bs.curve.Params.Gy) // should never happen
		if err != nil {
			continue
		}
		_, err = bs.curve.TestPoint(st.X, st.Y, rt.X, rt.Y) // should never happen
		if err != nil {
			continue
		}
		return rt, st, nil
	}
}
