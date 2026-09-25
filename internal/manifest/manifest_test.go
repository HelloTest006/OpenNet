package manifest

import (
	"bytes"
	"testing"

	"opennet/internal/cid"
	"opennet/internal/frame"
	"opennet/internal/member"
)

func signed(t *testing.T) (frame.Manifest, member.Identity) {
	t.Helper()
	pub, err := member.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	m := frame.Manifest{
		Name:   "news",
		Entry:  cid.Sum([]byte("home")),
		Blocks: []cid.ID{cid.Sum([]byte("home")), cid.Sum([]byte("style"))},
	}
	Sign(&m, pub)
	return m, pub
}

func TestSignAndVerify(t *testing.T) {
	m, pub := signed(t)
	if !bytes.Equal(m.PubKey, pub.Public) {
		t.Fatal("manifest key is not the publisher's")
	}
	if err := Verify(m); err != nil {
		t.Fatal(err)
	}

	// The wire round trip must preserve the signature.
	back, err := frame.UnmarshalManifest(m.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(back); err != nil {
		t.Fatalf("after round trip: %v", err)
	}
}

func TestTamperedNameRejected(t *testing.T) {
	m, _ := signed(t)
	m.Name = "hacked"
	if err := Verify(m); err != ErrUnsigned {
		t.Fatalf("altered name: got %v", err)
	}
}

func TestTamperedBlockRejected(t *testing.T) {
	m, _ := signed(t)
	m.Blocks = append(m.Blocks, cid.Sum([]byte("injected")))
	if err := Verify(m); err != ErrUnsigned {
		t.Fatalf("added block: got %v", err)
	}
}

func TestSwappedPublisherRejected(t *testing.T) {
	m, _ := signed(t)
	other, _ := member.NewIdentity()
	m.PubKey = other.Public
	if err := Verify(m); err != ErrUnsigned {
		t.Fatalf("swapped publisher: got %v", err)
	}
}

func TestBadKey(t *testing.T) {
	m, _ := signed(t)
	m.PubKey = []byte("short")
	if err := Verify(m); err != ErrPublisher {
		t.Fatalf("got %v", err)
	}
}
