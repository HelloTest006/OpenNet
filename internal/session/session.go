// Package session runs one peer connection: the handshake, then the
// exchange of manifests and blocks.
//
// A connection is two independent directions over one stream. Each side
// sends Hello first, reads the peer's Hello, and from then on every frame
// is a request or a response to one. Reads and writes each take the conn
// mutex, so a side can serve incoming requests while it waits on its own.
package session

import (
	"crypto/ed25519"
	"errors"
	"io"
	"sync"
	"time"

	"opennet/internal/cid"
	"opennet/internal/frame"
	"opennet/internal/member"
	"opennet/internal/store"
)

var (
	ErrRejected = errors.New("session: peer rejected")
	ErrBadBlock = errors.New("session: block bytes do not match its CID")
	ErrNoSite   = errors.New("session: site not found")
)

// Node is the local side of a session: who we are and what we hold.
type Node struct {
	// PubKey is the node's ed25519 public key. It is the node ID.
	PubKey []byte
	// Signer signs manifests this node publishes. It is not needed for a node
	// that only fetches.
	Signer member.Identity
	// Empty means the node is not asserting membership.
	Cert []byte
	// Trust is the set of authority public keys whose certificates this node
	// accepts, and Now supplies the time verification is judged against. Both
	// empty means the node does not check membership at all, which is only
	// appropriate for a node that has opted out of any network.
	Trust []ed25519.PublicKey
	Now   func() time.Time
	// Links are the transports this node can speak, advertised so a peer
	// can fall back from a custom radio to plain Wi-Fi.
	Links []string
	Store store.Store
	// Sites maps a site name to the raw, signed manifest bytes.
	Sites map[string][]byte
}

// Conn is one established session with a peer.
type Conn struct {
	node *Node
	rw   io.ReadWriter
	mu   sync.Mutex
	Peer frame.Hello
}

// Handshake sends our Hello and reads theirs. When this node trusts at least
// one authority, the peer is rejected unless its certificate was issued by one
// of them, is inside its validity window, and names the very key the peer
// claims as its identity. That last check is what stops a peer from presenting
// someone else's certificate.
func (n *Node) Handshake(rw io.ReadWriter) (*Conn, error) {
	c := &Conn{node: n, rw: rw}
	hello := frame.Hello{NodeID: n.PubKey, Cert: n.Cert, Links: n.Links}
	if err := c.send(frame.TypeHello, hello.Marshal()); err != nil {
		return nil, err
	}
	f, err := c.recv()
	if err != nil {
		return nil, err
	}
	if f.Type != frame.TypeHello {
		return nil, frame.ErrType
	}
	c.Peer, err = frame.UnmarshalHello(f.Payload)
	if err != nil {
		return nil, err
	}
	if len(n.Trust) > 0 {
		if err := admit(c.Peer, n.Trust, n.now()); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (n *Node) now() time.Time {
	if n.Now != nil {
		return n.Now()
	}
	return time.Now()
}

// admit decides whether a peer's claimed identity and certificate entitle it
// to a session.
func admit(h frame.Hello, trust []ed25519.PublicKey, now time.Time) error {
	if len(h.NodeID) != member.PubSize {
		return ErrRejected
	}
	cert, err := member.UnmarshalCert(h.Cert)
	if err != nil {
		return ErrRejected
	}
	node := ed25519.PublicKey(append([]byte(nil), h.NodeID...))
	if err := member.Verify(cert, trust, node, now); err != nil {
		return ErrRejected
	}
	return nil
}

// Serve reads requests until the peer closes and answers each one. It
// blocks, so run it in its own goroutine.
func (c *Conn) Serve() error {
	for {
		f, err := c.recv()
		if err != nil {
			return err
		}
		if err := c.handle(f); err != nil {
			return err
		}
	}
}

func (c *Conn) handle(f frame.Frame) error {
	switch f.Type {
	case frame.TypeResolve:
		q, err := frame.UnmarshalResolve(f.Payload)
		if err != nil {
			return err
		}
		raw, ok := c.node.Sites[q.Name]
		if !ok {
			return c.send(frame.TypeManifest, nil)
		}
		return c.send(frame.TypeManifest, raw)
	case frame.TypeWant:
		w, err := frame.UnmarshalWant(f.Payload)
		if err != nil {
			return err
		}
		for _, id := range w.CIDs {
			data, err := c.node.Store.Get(id)
			if err != nil {
				continue
			}
			if err := c.send(frame.TypeBlock, frame.Block{CID: id, Data: data}.Marshal()); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

// FetchSite asks the peer for a site by name and returns the raw manifest
// bytes. A zero-length manifest means the peer doesn't carry that site.
func (c *Conn) FetchSite(name string) ([]byte, error) {
	if err := c.send(frame.TypeResolve, frame.Resolve{Name: name}.Marshal()); err != nil {
		return nil, err
	}
	f, err := c.recvType(frame.TypeManifest)
	if err != nil {
		return nil, err
	}
	if len(f.Payload) == 0 {
		return nil, ErrNoSite
	}
	return f.Payload, nil
}

// FetchBlocks requests blocks and returns them keyed by CID. A block whose
// bytes don't hash to the CID it claims is rejected rather than stored:
// the peer is untrusted, the hash is the check.
func (c *Conn) FetchBlocks(ids []cid.ID) (map[cid.ID][]byte, error) {
	if err := c.send(frame.TypeWant, frame.Want{CIDs: ids}.Marshal()); err != nil {
		return nil, err
	}
	out := make(map[cid.ID][]byte, len(ids))
	for len(out) < len(ids) {
		f, err := c.recvType(frame.TypeBlock)
		if err != nil {
			return out, err
		}
		b, err := frame.UnmarshalBlock(f.Payload)
		if err != nil {
			return out, err
		}
		if cid.Sum(b.Data) != b.CID {
			return out, ErrBadBlock
		}
		out[b.CID] = b.Data
	}
	return out, nil
}

func (c *Conn) send(t frame.Type, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return frame.Write(c.rw, frame.Frame{Type: t, Payload: payload})
}

func (c *Conn) recv() (frame.Frame, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return frame.Read(c.rw)
}

func (c *Conn) recvType(t frame.Type) (frame.Frame, error) {
	f, err := c.recv()
	if err != nil {
		return f, err
	}
	if f.Type != t {
		return f, frame.ErrType
	}
	return f, nil
}
