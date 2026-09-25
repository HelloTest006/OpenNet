package member

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

func TestIssueAndVerify(t *testing.T) {
	ca, err := NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_000_000, 0)
	cert, err := ca.Issue(node.Public, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	back, err := UnmarshalCert(cert.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(back, []ed25519.PublicKey{ca.Public}, node.Public, now); err != nil {
		t.Fatal(err)
	}

	if err := Verify(back, []ed25519.PublicKey{ca.Public}, node.Public, now.Add(2*time.Hour)); err != ErrExpired {
		t.Fatalf("expired cert: got %v", err)
	}
	if err := Verify(back, []ed25519.PublicKey{ca.Public}, node.Public, now.Add(-2*time.Hour)); err != ErrNotYet {
		t.Fatalf("early cert: got %v", err)
	}
}

func TestForeignAuthorityRejected(t *testing.T) {
	ca, _ := NewAuthority()
	other, _ := NewAuthority()
	node, _ := NewIdentity()
	now := time.Unix(1_000_000, 0)

	cert, err := other.Issue(node.Public, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(cert, []ed25519.PublicKey{ca.Public}, node.Public, now); err != ErrUntrusted {
		t.Fatalf("foreign issuer: got %v", err)
	}
}

func TestWrongNodeRejected(t *testing.T) {
	ca, _ := NewAuthority()
	node, _ := NewIdentity()
	impostor, _ := NewIdentity()
	now := time.Unix(1_000_000, 0)

	cert, _ := ca.Issue(node.Public, now.Add(-time.Hour), now.Add(time.Hour))
	if err := Verify(cert, []ed25519.PublicKey{ca.Public}, impostor.Public, now); err != ErrIdentity {
		t.Fatalf("cert presented by the wrong node: got %v", err)
	}
}

func TestTamperedSignatureRejected(t *testing.T) {
	ca, _ := NewAuthority()
	node, _ := NewIdentity()
	now := time.Unix(1_000_000, 0)

	cert, _ := ca.Issue(node.Public, now.Add(-time.Hour), now.Add(time.Hour))
	raw := cert.Marshal()
	raw[len(raw)-1] ^= 0xff
	back, err := UnmarshalCert(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(back, []ed25519.PublicKey{ca.Public}, node.Public, now); err != ErrSignature {
		t.Fatalf("tampered cert: got %v", err)
	}
}

func TestMalformed(t *testing.T) {
	if _, err := UnmarshalCert([]byte("nope")); err != ErrBadCert {
		t.Fatalf("got %v", err)
	}
	if _, err := UnmarshalCert(bytes.Repeat([]byte{0}, PubSize*2+16+SigSize-1)); err != ErrBadCert {
		t.Fatalf("short cert accepted")
	}
}
