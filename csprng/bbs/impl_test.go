package bbs

import (
	"bytes"
	"testing"
)

func TestParams(t *testing.T) {
	p, q, x := Params(64)
	bbs := New(p, q, x)
	r := bbs.Bytes(32)
	bbs2 := New(p, q, x)
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
}
