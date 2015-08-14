// Package bbs implements the Blum-Blum-Shub pseudo-random number generator. The implementation should be considered
// to be insecure.
// x(n+1)=x(n)^2 mod (p*q).  p,q are large primes,
// gcd(φ(p − 1), φ(q − 1)) should be small. p and q, should both be congruent to 3 (mod 4)
// initial seed xn should be neither 1 or 0, and not divisible by p or q.
// xi = x0^(2^i mod lcm(p-1,q-1)) mod p*q
package bbs

import (
	"crypto/rand"
	"math"
	"math/big"
	"sync"
)

var (
	zero  = big.NewInt(0)
	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)
	four  = big.NewInt(4)
	ceil  = big.NewInt(3) // That's the smallest GCD possible
)

// BBS contains the state of a Blum-Blum-Shub
type BBS struct {
	xn      *big.Int // last x
	X0      *big.Int // x at 0
	M       *big.Int // M = p*q
	L       *big.Int // lcm(p-1,q-1)
	rlock   *sync.Mutex
	Step    uint64
	Maxbits int // log (bits M)
}

func lcmMinusOne(a, b *big.Int) *big.Int {
	a1 := new(big.Int).Sub(a, one)
	b1 := new(big.Int).Sub(b, one)
	mul := new(big.Int).Mul(a1, b1)
	gcd := new(big.Int).GCD(nil, nil, a1, b1)
	return new(big.Int).Div(mul, gcd)
}

// return a likely prime that is congruent 3 mod 4
func getPrime(bits int) *big.Int {
	var err error
	p := new(big.Int)
	for {
		p, err = rand.Prime(rand.Reader, bits)
		if err != nil {
			panic("rand reader failed")
		}
		p3 := new(big.Int).Mod(new(big.Int).Sub(p, three), four)
		if p3.Cmp(zero) == 0 {
			return p
		}
	}
}

func calcX(p, q *big.Int) *big.Int {
	var err error
	var x *big.Int
	max := q
	if p.Cmp(q) > 0 {
		max = p
	}
	for {
		x, err = rand.Int(rand.Reader, max)
		if err != nil {
			panic("rand reader failed")
		}
		if x.Cmp(one) == 0 || x.Cmp(zero) == 0 {
			continue
		}
		if new(big.Int).Div(x, p).Cmp(zero) > 0 {
			continue
		}
		if new(big.Int).Div(x, q).Cmp(zero) > 0 {
			continue
		}
		return x
	}
}

// Params generates new BBS params
func Params(bits int) (p, q, x *big.Int) {
	p, q = new(big.Int), new(big.Int)
	p = getPrime(bits)
	for {
		q = getPrime(bits)
		p1 := new(big.Int).Sub(p, one)
		q1 := new(big.Int).Sub(q, one)
		gcd := new(big.Int).GCD(nil, nil, p1, q1)
		if gcd.Cmp(ceil) == -1 { // that's almost not necessary
			break
		}
	}
	x = calcX(p, q)
	return p, q, x
}

// New sets up a new BBS
func New(p, q, x *big.Int) *BBS {
	bbs := new(BBS)
	bbs.X0 = x
	bbs.M = new(big.Int).Mul(p, q)
	bbs.L = lcmMinusOne(p, q)
	bbs.Maxbits = int(math.Log(float64(bbs.M.BitLen())))
	bbs.rlock = new(sync.Mutex)
	return bbs
}

func (bbs *BBS) step() {
	var x *big.Int
	bbs.Step++
	x = bbs.xn
	if bbs.xn == nil {
		x = bbs.X0
	}
	bbs.xn = new(big.Int).Exp(x, two, bbs.M)
}

// bits returns Maxbits next random bits, rounded up to the next byte
func (bbs *BBS) bits() []byte {
	bbs.step()
	fullBytes := bbs.Maxbits / 8
	missingBits := bbs.Maxbits % 8
	if missingBits > 0 {
		fullBytes++
	}
	d := bbs.xn.Bytes()
	if len(d) < fullBytes {
		fullBytes = len(d)
	}
	dn := d[len(d)-fullBytes:]
	return dn
}

// Bytes returns n bytes of random data from the generator
func (bbs *BBS) Bytes(n int) []byte {
	bbs.rlock.Lock()
	defer bbs.rlock.Unlock()
	return bbs.bytes(n)
}

func (bbs *BBS) bytes(n int) []byte {
	ret := make([]byte, 0, n)
	for {
		x := bbs.bits()
		ret = append(ret, x...)
		if len(ret) >= n {
			break
		}
	}
	return ret[:n]
}

// BytesAt returns m bytes from position xn. This moves the whole generator to n.
func (bbs *BBS) BytesAt(n int64, m int) []byte {
	// xi = x0^(2^i mod lcm(p-1,q-1)) mod p*q
	bbs.rlock.Lock()
	defer bbs.rlock.Unlock()
	pos := new(big.Int).Exp(two, big.NewInt(n), bbs.L)
	bbs.xn = new(big.Int).Exp(bbs.X0, pos, bbs.M)
	b := bbs.bytes(m)
	return b
}
