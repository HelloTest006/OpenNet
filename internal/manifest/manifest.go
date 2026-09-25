// Package manifest is a signed site description.
//
// A manifest names a site and every block it is made of, and carries the
// publisher's ed25519 signature over all of that. The signature is what makes
// relaying safe: a node can pass a site along without being trusted, because
// any change to the name, the publisher, or the set of blocks invalidates the
// signature. A relay can refuse to carry a site, but it cannot alter one
// without the receiver noticing.
//
// The signed bytes are the manifest's wire encoding with the signature field
// empty, so there is exactly one layout and the frame package owns it.
package manifest

import (
	"crypto/ed25519"
	"errors"

	"opennet/internal/frame"
	"opennet/internal/member"
)

var (
	ErrUnsigned  = errors.New("manifest: not signed by the claimed publisher")
	ErrPublisher = errors.New("manifest: publisher key is not a valid ed25519 key")
)

// Site is a verified site: a manifest whose signature has been checked.
type Site struct {
	frame.Manifest
}

// Sign fills in the publisher's signature. pub must be the private key behind
// m.PubKey; the signature is over the encoding of the manifest with an empty
// signature field.
func Sign(m *frame.Manifest, pub member.Identity) {
	m.PubKey = pub.Public
	m.Sig = nil
	m.Sig = pub.Sign(m.Marshal())
}

// Verify checks that the manifest was signed by the key it names. It says
// nothing about whether that publisher is anyone in particular — that is a
// trust decision the caller makes. It only guarantees the manifest is intact
// and came from the holder of that key.
func Verify(m frame.Manifest) error {
	if len(m.PubKey) != ed25519.PublicKeySize {
		return ErrPublisher
	}
	sig := m.Sig
	m.Sig = nil
	if !ed25519.Verify(m.PubKey, m.Marshal(), sig) {
		return ErrUnsigned
	}
	return nil
}
