// Package member is how a node proves it belongs to a network.
//
// A certificate binds a node's ed25519 public key to a membership for a
// window of time, and is signed by a certificate authority. A node accepts a
// peer only when three things hold: the certificate names the key the peer
// claims as its identity, the signature verifies under an authority the node
// trusts, and the certificate has not expired.
//
// That is the whole mechanism, and it is the same for both kinds of network.
// A private network trusts one authority it does not share; the open community
// trusts an authority whose public key is distributed widely. The difference
// is who holds the authority key, not the format.
//
// What this cannot do is worth stating next to the code that doesn't do it. A
// certificate proves identity, not scarcity: nothing stops someone from asking
// the authority for many certificates, so a certificate alone never limits how
// much traffic one party can send. Rate limiting is a separate concern.
// Expiry is the revocation mechanism — certificates are meant to be short
// lived, so a leaked one dies on its own rather than needing a revocation list
// every node must learn about.
package member

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"
)

const (
	// PubSize is the length of an ed25519 public key.
	PubSize = ed25519.PublicKeySize
	// SigSize is the length of an ed25519 signature.
	SigSize = ed25519.SignatureSize
)

var (
	ErrBadKey    = errors.New("member: not an ed25519 public key")
	ErrBadCert   = errors.New("member: malformed certificate")
	ErrSignature = errors.New("member: signature does not verify")
	ErrExpired   = errors.New("member: certificate has expired")
	ErrNotYet    = errors.New("member: certificate is not valid yet")
	ErrUntrusted = errors.New("member: issuer is not a trusted authority")
	ErrIdentity  = errors.New("member: certificate is not for this node")
)

// Identity is a node's long-term key. The public key is the node ID.
type Identity struct {
	Public  ed25519.PublicKey
	private ed25519.PrivateKey
}

// NewIdentity generates a node identity from the system random source.
func NewIdentity() (Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Public: pub, private: priv}, nil
}

// Sign signs msg with the identity's private key.
func (id Identity) Sign(msg []byte) []byte { return ed25519.Sign(id.private, msg) }

// Private returns the identity's private key, for storage.
func (id Identity) Private() []byte { return id.private }

// ParseIdentity reads an identity file: the private key followed by the
// membership certificate. The certificate is returned raw because the session
// layer carries it verbatim.
func ParseIdentity(b []byte) (Identity, []byte, error) {
	if len(b) < ed25519.PrivateKeySize {
		return Identity{}, nil, ErrBadKey
	}
	key := ed25519.PrivateKey(append([]byte(nil), b[:ed25519.PrivateKeySize]...))
	id := Identity{Public: key.Public().(ed25519.PublicKey), private: key}
	cert := append([]byte(nil), b[ed25519.PrivateKeySize:]...)
	if _, err := UnmarshalCert(cert); err != nil {
		return Identity{}, nil, err
	}
	return id, cert, nil
}

// Authority is a certificate authority. Its public key is what nodes trust;
// its private key is what issues certificates, and only the operator of a
// network holds it.
type Authority struct {
	Public  ed25519.PublicKey
	private ed25519.PrivateKey
}

// Private returns the authority's private key, for storage. The public key is
// its first ed25519.PublicKeySize bytes, so this is all a node needs to trust
// the authority too.
func (a Authority) Private() []byte { return a.private }

// AuthorityFrom reconstructs an authority from its stored private key.
func AuthorityFrom(priv []byte) (Authority, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Authority{}, ErrBadKey
	}
	key := ed25519.PrivateKey(append([]byte(nil), priv...))
	return Authority{Public: key.Public().(ed25519.PublicKey), private: key}, nil
}

// NewAuthority generates a certificate authority.
func NewAuthority() (Authority, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Authority{}, err
	}
	return Authority{Public: pub, private: priv}, nil
}

// Cert is a membership certificate. Times are unix seconds.
type Cert struct {
	// Node is the public key this certificate grants membership to.
	Node ed25519.PublicKey
	// Issuer is the authority that signed it.
	Issuer ed25519.PublicKey
	// NotBefore and NotAfter bound the validity window, unix seconds.
	NotBefore int64
	NotAfter  int64
	// Sig is the issuer's signature over the fields above.
	Sig []byte
}

// Issue signs a certificate granting id membership over [notBefore, notAfter).
func (a Authority) Issue(node ed25519.PublicKey, notBefore, notAfter time.Time) (Cert, error) {
	if len(node) != PubSize {
		return Cert{}, ErrBadKey
	}
	c := Cert{
		Node:      node,
		Issuer:    a.Public,
		NotBefore: notBefore.Unix(),
		NotAfter:  notAfter.Unix(),
	}
	c.Sig = ed25519.Sign(a.private, c.signed())
	return c, nil
}

// signed is the exact byte string the signature covers: both keys and both
// timestamps, and never the signature itself.
func (c Cert) signed() []byte {
	b := make([]byte, 0, PubSize*2+16)
	b = append(b, c.Node...)
	b = append(b, c.Issuer...)
	b = binary.BigEndian.AppendUint64(b, uint64(c.NotBefore))
	b = binary.BigEndian.AppendUint64(b, uint64(c.NotAfter))
	return b
}

// Marshal encodes the certificate for the wire. The layout is fixed-width
// apart from nothing: two keys, two timestamps, one signature.
func (c Cert) Marshal() []byte {
	b := make([]byte, 0, PubSize*2+16+SigSize)
	b = append(b, c.signed()...)
	b = append(b, c.Sig...)
	return b
}

// UnmarshalCert decodes a certificate. It checks the structure only, not the
// signature or the validity window; call Verify for that.
func UnmarshalCert(b []byte) (Cert, error) {
	if len(b) != PubSize*2+16+SigSize {
		return Cert{}, ErrBadCert
	}
	c := Cert{
		Node:   append(ed25519.PublicKey(nil), b[:PubSize]...),
		Issuer: append(ed25519.PublicKey(nil), b[PubSize:PubSize*2]...),
	}
	b = b[PubSize*2:]
	c.NotBefore = int64(binary.BigEndian.Uint64(b))
	c.NotAfter = int64(binary.BigEndian.Uint64(b[8:]))
	c.Sig = append([]byte(nil), b[16:]...)
	return c, nil
}

// Verify checks the certificate against the authorities a node trusts, at
// time now. trusted is the set of authority public keys the node accepts; a
// private network passes one, the open community passes the community
// authority. node, when non-nil, additionally requires the certificate to
// name that exact key, which is how a handshake ties the certificate to the
// identity the peer just claimed.
func Verify(c Cert, trusted []ed25519.PublicKey, node ed25519.PublicKey, now time.Time) error {
	if len(c.Node) != PubSize || len(c.Issuer) != PubSize || len(c.Sig) != SigSize {
		return ErrBadCert
	}
	if node != nil && !c.Node.Equal(node) {
		return ErrIdentity
	}
	if !trustedIssuer(c.Issuer, trusted) {
		return ErrUntrusted
	}
	t := now.Unix()
	if t < c.NotBefore {
		return ErrNotYet
	}
	if t >= c.NotAfter {
		return ErrExpired
	}
	if !ed25519.Verify(c.Issuer, c.signed(), c.Sig) {
		return ErrSignature
	}
	return nil
}

func trustedIssuer(issuer ed25519.PublicKey, trusted []ed25519.PublicKey) bool {
	for _, t := range trusted {
		if issuer.Equal(t) {
			return true
		}
	}
	return false
}
