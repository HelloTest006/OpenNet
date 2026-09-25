// Package frame is the on-wire codec. Every frame is
//
//	u32be length | u8 type | payload
//
// where length counts type and payload together, so a reader can skip a
// frame it does not understand. Payloads are length-prefixed fields, big
// endian throughout, with no compression and no framing inside framing.
package frame

import (
	"encoding/binary"
	"errors"
	"io"

	"opennet/internal/cid"
)

type Type uint8

const (
	TypeHello    Type = 1
	TypeHave     Type = 2
	TypeWant     Type = 3
	TypeBlock    Type = 4
	TypeResolve  Type = 5
	TypeManifest Type = 6
)

const (
	headerSize = 5 // u32 length + u8 type
	maxPayload = 8 << 20
)

var (
	ErrTooLarge = errors.New("frame: payload exceeds limit")
	ErrTrunc    = errors.New("frame: truncated field")
	ErrType     = errors.New("frame: unexpected type")
)

type Frame struct {
	Type    Type
	Payload []byte
}

func Write(w io.Writer, f Frame) error {
	if len(f.Payload)+1 > maxPayload {
		return ErrTooLarge
	}
	var hdr [headerSize]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(f.Payload)+1))
	hdr[4] = byte(f.Type)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(f.Payload)
	return err
}

func Read(r io.Reader) (Frame, error) {
	var hdr [headerSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n == 0 || int(n) > maxPayload {
		return Frame{}, ErrTooLarge
	}
	payload := make([]byte, n-1)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}
	return Frame{Type: Type(hdr[4]), Payload: payload}, nil
}

// buf accumulates a payload. It exists so encoders don't each reimplement
// big-endian field writing.
type buf struct{ b []byte }

func (p *buf) u8(v uint8)   { p.b = append(p.b, v) }
func (p *buf) u16(v uint16) { p.b = binary.BigEndian.AppendUint16(p.b, v) }
func (p *buf) u32(v uint32) { p.b = binary.BigEndian.AppendUint32(p.b, v) }
func (p *buf) u64(v uint64) { p.b = binary.BigEndian.AppendUint64(p.b, v) }
func (p *buf) raw(b []byte) { p.b = append(p.b, b...) }
func (p *buf) bytes(b []byte) {
	p.u32(uint32(len(b)))
	p.b = append(p.b, b...)
}
func (p *buf) str(s string) { p.bytes([]byte(s)) }

// rdr reads fields back. err sticks: once set, every method returns zero so
// a decode can run straight through and check once at the end.
type rdr struct {
	b   []byte
	err error
}

func (r *rdr) need(n int) bool {
	if r.err != nil {
		return false
	}
	if len(r.b) < n {
		r.err = ErrTrunc
		return false
	}
	return true
}

func (r *rdr) u8() uint8 {
	if !r.need(1) {
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *rdr) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *rdr) u32() uint32 {
	if !r.need(4) {
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *rdr) u64() uint64 {
	if !r.need(8) {
		return 0
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

func (r *rdr) raw(n int) []byte {
	if !r.need(n) {
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *rdr) bytes() []byte {
	n := r.u32()
	if r.err != nil {
		return nil
	}
	return r.raw(int(n))
}

func (r *rdr) str() string { return string(r.bytes()) }

func (r *rdr) cid() cid.ID {
	var id cid.ID
	copy(id[:], r.raw(cid.Size))
	return id
}

// Hello is the first frame each side sends. NodeID is the peer's ed25519
// public key; Cert is its membership certificate, opaque here.
type Hello struct {
	NodeID []byte
	Cert   []byte
	Links  []string
}

func (h Hello) Marshal() []byte {
	var p buf
	p.bytes(h.NodeID)
	p.bytes(h.Cert)
	p.u16(uint16(len(h.Links)))
	for _, l := range h.Links {
		p.str(l)
	}
	return p.b
}

func UnmarshalHello(b []byte) (Hello, error) {
	r := rdr{b: b}
	h := Hello{NodeID: r.bytes(), Cert: r.bytes()}
	n := r.u16()
	for i := 0; i < int(n) && r.err == nil; i++ {
		h.Links = append(h.Links, r.str())
	}
	return h, r.err
}

// Have lists the CIDs a node holds. Milestone 1 sends them verbatim; the
// invertible-bloom summary replaces this payload later without a new type.
type Have struct{ CIDs []cid.ID }

func (h Have) Marshal() []byte {
	var p buf
	p.u32(uint32(len(h.CIDs)))
	for _, c := range h.CIDs {
		p.raw(c[:])
	}
	return p.b
}

func UnmarshalHave(b []byte) (Have, error) {
	r := rdr{b: b}
	n := r.u32()
	h := Have{CIDs: make([]cid.ID, 0, n)}
	for i := 0; i < int(n) && r.err == nil; i++ {
		h.CIDs = append(h.CIDs, r.cid())
	}
	return h, r.err
}

type Want struct{ CIDs []cid.ID }

func (w Want) Marshal() []byte { return Have{CIDs: w.CIDs}.Marshal() }
func UnmarshalWant(b []byte) (Want, error) {
	h, err := UnmarshalHave(b)
	return Want{CIDs: h.CIDs}, err
}

// Block carries one chunk of content. Data is the raw, uncompressed bytes;
// the receiver recomputes the CID and discards the block if it differs.
type Block struct {
	CID  cid.ID
	Data []byte
}

func (b Block) Marshal() []byte {
	var p buf
	p.raw(b.CID[:])
	p.bytes(b.Data)
	return p.b
}

func UnmarshalBlock(b []byte) (Block, error) {
	r := rdr{b: b}
	blk := Block{CID: r.cid(), Data: r.bytes()}
	return blk, r.err
}

// Resolve asks a peer which manifest backs a site name.
type Resolve struct{ Name string }

func (q Resolve) Marshal() []byte {
	var p buf
	p.str(q.Name)
	return p.b
}

func UnmarshalResolve(b []byte) (Resolve, error) {
	r := rdr{b: b}
	q := Resolve{Name: r.str()}
	return q, r.err
}

// Manifest is a site: a name, the publisher's public key, the CID of the
// entry block, every block the site references, and the publisher's
// signature over the preceding fields. The signature is verified by the
// manifest package; here it is only carried.
type Manifest struct {
	Name   string
	PubKey []byte
	Entry  cid.ID
	Blocks []cid.ID
	Sig    []byte
}

func (m Manifest) Marshal() []byte {
	var p buf
	p.str(m.Name)
	p.bytes(m.PubKey)
	p.raw(m.Entry[:])
	p.u32(uint32(len(m.Blocks)))
	for _, c := range m.Blocks {
		p.raw(c[:])
	}
	p.bytes(m.Sig)
	return p.b
}

func UnmarshalManifest(b []byte) (Manifest, error) {
	r := rdr{b: b}
	m := Manifest{Name: r.str(), PubKey: r.bytes(), Entry: r.cid()}
	n := r.u32()
	for i := 0; i < int(n) && r.err == nil; i++ {
		m.Blocks = append(m.Blocks, r.cid())
	}
	m.Sig = r.bytes()
	return m, r.err
}
