// Package bbs implements the Blum-Blum-Shub pseudo-random number generator. The implementation should be considered
// to be insecure.
// x(n+1)=x(n)^2 mod (p*q).  p,q are large primes,
// gcd(φ(p − 1), φ(q − 1)) should be small. p and q, should both be congruent to 3 (mod 4)
// initial seed xn should be neither 1 or 0, and not divisible by p or q.
// xi = x0^(2^i mod lcm(p-1,q-1)) mod p*q
package bbs

import (
	"crypto/rand"
	"io"
	"math"
	"math/big"
	"sync"
)

var (
	// Some  big.Int constants
	zero  = big.NewInt(0)
	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)
	four  = big.NewInt(4)
	ceil  = big.NewInt(3) // That's the smallest GCD possible
)

// Reader is a conveniance reader
var Reader io.Reader

// Rand is the upstream random source for initialisation
var Rand = rand.Reader

func init() {
	// Set up a small/less secure global random source
	b := New(Params(128, 0))
	Reader = b
}

// BBS contains the state of a Blum-Blum-Shub
type BBS struct {
	xn      *big.Int // last x
	X0      *big.Int // x at 0
	M       *big.Int // M = p*q
	L       *big.Int // lcm(p-1,q-1)
	rlock   *sync.Mutex
	Step    int64
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
		p, err = rand.Prime(Rand, bits)
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
		x, err = rand.Int(Rand, max)
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

// Params generates new BBS params. bits is the number of bits that initial values should have (the more the better),
// step is the step to which the RNG should jump when using it like this: New(Params(bits,lastStep))
func Params(bits int, lastStep int64) (p, q, x *big.Int, step int64) {
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
	return p, q, x, lastStep
}

// New sets up a new BBS
func New(p, q, x *big.Int, step int64) *BBS {
	bbs := new(BBS)
	bbs.X0 = x
	bbs.M = new(big.Int).Mul(p, q)
	bbs.L = lcmMinusOne(p, q)
	bbs.Maxbits = int(math.Log(float64(bbs.M.BitLen())))
	mbits := bbs.Maxbits % 8
	mbytes := bbs.Maxbits / 8
	if mbits > 0 {
		mbytes++
	}
	bbs.Step = int64(
		math.Pow(float64(p.BitLen()), 2)*
			math.Pow(float64(q.BitLen()), 2)*
			math.Pow(float64(x.BitLen()), 2)) / int64((mbytes*8*2)/bbs.Maxbits)

	bbs.rlock = new(sync.Mutex)
	if step > 0 {
		bbs.BytesAt(bbs.Step-step, 1)
	}
	return bbs
}

func (bbs *BBS) step() {
	var x *big.Int
	if bbs.Step == 1 {
		panic("RNG Exhausted!!!")
	}
	bbs.Step--
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

// Read implements BBS as io.Reader as drop-in RNG
func (bbs *BBS) Read(p []byte) (n int, err error) {
	l := len(p)
	copy(p, bbs.Bytes(l))
	return l, nil
}
