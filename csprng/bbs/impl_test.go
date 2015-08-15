package bbs

import (
	"bytes"
	"testing"
)

func TestParams(t *testing.T) {
	p, q, x, _ := Params(64, 0)
	bbs := New(p, q, x, 0)
	r := bbs.Bytes(32)
	bbs2 := New(p, q, x, 0)
	r2 := bbs2.Bytes(32)
	if !bytes.Equal(r, r2) {
		t.Error("Bad bytes")
	}
	t1 := bbs.BytesAt(10012, 12)
	t2 := bbs.BytesAt(10018, 12)
	if !bytes.Equal(t1[6:], t2[:6]) {
		t.Error("BytesAt incorrect for positional/positional")
	}
	t3 := bbs.BytesAt(0, 32)
	if !bytes.Equal(r, t3) {
		t.Error("BytesAt incorrect for positional/non-positional")
	}
	t3 = bbs.BytesAt(1, 32)
	if bytes.Equal(r, t3) {
		t.Error("BytesAt incorrect, shift may not match")
	}
	t3 = bbs.BytesAt(31, 32)
	if bytes.Equal(r, t3) {
		t.Error("BytesAt incorrect, shift may not match")
	}
	t3 = bbs.BytesAt(32, 32)
	if bytes.Equal(r, t3) {
		t.Error("BytesAt incorrect, shift may not match")
	}
	t3 = bbs.BytesAt(33, 32)
	if bytes.Equal(r, t3) {
		t.Error("BytesAt incorrect, shift may not match")
	}
	b := make([]byte, 10)
	bbs.Read(b)
	if bytes.Equal(b, make([]byte, 10)) {
		t.Error("Read returns zeros")
	}
	b = make([]byte, 10)
	Reader.Read(b)
	if bytes.Equal(b, make([]byte, 10)) {
		t.Error("Read returns zeros")
	}
	c := make([]byte, 10)
	Reader.Read(c)
	if bytes.Equal(c, make([]byte, 10)) {
		t.Error("Read returns zeros")
	}
	if bytes.Equal(b, c) {
		t.Error("RNG produces repetition")
	}
}
