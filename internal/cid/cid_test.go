package cid

import "testing"

func TestSumStable(t *testing.T) {
	a := Sum([]byte("opennet"))
	b := Sum([]byte("opennet"))
	if a != b {
		t.Fatal("same bytes produced different CIDs")
	}
	if a == Sum([]byte("openneT")) {
		t.Fatal("different bytes produced the same CID")
	}
	if a.IsZero() {
		t.Fatal("hash of non-empty input is zero")
	}
}

func TestParseRoundTrip(t *testing.T) {
	id := Sum([]byte("block"))
	back, err := Parse(id.String())
	if err != nil {
		t.Fatal(err)
	}
	if back != id {
		t.Fatalf("round trip mismatch: %s != %s", back, id)
	}
	if _, err := Parse("abcd"); err == nil {
		t.Fatal("short string accepted")
	}
	if _, err := Parse("zz"); err == nil {
		t.Fatal("non-hex accepted")
	}
}
