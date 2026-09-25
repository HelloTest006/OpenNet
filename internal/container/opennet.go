// Package container reads and writes .opennet files.
//
// A .opennet file is one node's slice of the corpus, stored so a block can be
// fetched by its CID with a single binary search and one seek rather than by
// unpacking the file. The layout, from the start of the file:
//
//	magic "ONET" | u8 version | u8 flags | u32 dict_len | zstd dictionary
//	blob region: repeated  cid(32) | u64 raw_len | u32 comp_len | zstd(blob)
//	index:       u32 count, then count entries of cid(32) | u64 offset | u32 length,
//	             sorted by CID
//	footer:      u64 index_offset | magic "ONET"
//
// offset is the position of the blob's compressed bytes and length is
// comp_len, so a lookup seeks straight to the data.
//
// Two things make the file smaller than the sum of its sites. Blocks are
// stored by CID, so an asset shared by many sites is stored once. And the
// dictionary is trained on the text in the corpus, which is what makes many
// pages that share a template cheap; it does little for images, and those are
// stored as-is.
package container

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sort"

	"github.com/klauspost/compress/zstd"

	"opennet/internal/cid"
)

const (
	magic   = "ONET"
	version = 1
	// flagDict marks a file whose dictionary slot is populated.
	flagDict = 1
)

var (
	ErrFormat  = errors.New("opennet: not an .opennet file")
	ErrVersion = errors.New("opennet: unsupported version")
)

// Blob is one block to be written: its raw bytes. The CID is derived, so the
// caller cannot claim an identity for bytes that don't have it.
type Blob struct {
	Data []byte
}

// Writer builds an .opennet file. Blobs are buffered so the dictionary can be
// trained on all of them before anything is written.
type Writer struct {
	blobs [][]byte
	seen  map[cid.ID]struct{}
}

// NewWriter returns an empty writer.
func NewWriter() *Writer {
	return &Writer{seen: map[cid.ID]struct{}{}}
}

// Add queues a block. A block already queued with the same bytes is skipped,
// which is the dedup.
func (w *Writer) Add(data []byte) cid.ID {
	id := cid.Sum(data)
	if _, ok := w.seen[id]; ok {
		return id
	}
	stored := make([]byte, len(data))
	copy(stored, data)
	w.blobs = append(w.blobs, stored)
	w.seen[id] = struct{}{}
	return id
}

// Count is the number of distinct blocks queued.
func (w *Writer) Count() int { return len(w.blobs) }

type entry struct {
	id     cid.ID
	offset uint64
	length uint32
	raw    uint64
}

// WriteTo trains a dictionary, compresses every block with it, and writes the
// file to dst. It returns the number of bytes written.
func (w *Writer) WriteTo(dst io.Writer) (int64, error) {
	dict := train(w.blobs)
	enc, err := encoder(dict)
	if err != nil {
		return 0, err
	}
	defer enc.Close()

	var buf bytes.Buffer
	buf.WriteString(magic)
	buf.WriteByte(version)
	flags := byte(0)
	if dict != nil {
		flags = flagDict
	}
	buf.WriteByte(flags)
	var dl [4]byte
	binary.BigEndian.PutUint32(dl[:], uint32(len(dict)))
	buf.Write(dl[:])
	buf.Write(dict)

	entries := make([]entry, 0, len(w.blobs))
	for _, b := range w.blobs {
		compressed := enc.EncodeAll(b, nil)
		e := entry{
			id:     cid.Sum(b),
			offset: uint64(buf.Len()) + 32 + 8 + 4,
			length: uint32(len(compressed)),
			raw:    uint64(len(b)),
		}
		buf.Write(e.id[:])
		var lens [12]byte
		binary.BigEndian.PutUint64(lens[:8], e.raw)
		binary.BigEndian.PutUint32(lens[8:], e.length)
		buf.Write(lens[:])
		buf.Write(compressed)
		entries = append(entries, e)
	}

	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].id[:], entries[j].id[:]) < 0 })

	indexAt := uint64(buf.Len())
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(entries)))
	buf.Write(count[:])
	for _, e := range entries {
		var rec [44]byte
		copy(rec[:32], e.id[:])
		binary.BigEndian.PutUint64(rec[32:40], e.offset)
		binary.BigEndian.PutUint32(rec[40:], e.length)
		buf.Write(rec[:])
	}

	var footer [12]byte
	binary.BigEndian.PutUint64(footer[:8], indexAt)
	copy(footer[8:], magic)
	buf.Write(footer[:])

	n, err := dst.Write(buf.Bytes())
	return int64(n), err
}

// WriteFile writes the file at path, creating or truncating it.
func (w *Writer) WriteFile(path string) (int64, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	n, err := w.WriteTo(f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return n, err
}

// dictSize caps the trained dictionary. It has to stay far smaller than the
// corpus or the dictionary costs more than it saves.
const dictSize = 64 << 10

// dictID is this format's dictionary identifier, fixed so a decoder knows
// which dictionary a frame refers to.
const dictID = 0x4F4E4554 // "ONET"

// train builds a dictionary from the text-like blocks. The dictionary content
// is the recurring structure itself: zstd then uses it as prior history when
// compressing every block, which is exactly the saving when many pages share a
// template. Binary blocks are left out, since a dictionary learns patterns that
// recur and compressed images have none.
func train(blobs [][]byte) []byte {
	var samples [][]byte
	seen := map[cid.ID]struct{}{}
	var hist []byte
	for _, b := range blobs {
		if len(b) == 0 || len(b) > 256<<10 || !textual(b) {
			continue
		}
		samples = append(samples, b)
		// The history only needs each distinct chunk once; repeating it adds
		// nothing and can push the dictionary past its size limit.
		id := cid.Sum(b)
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if len(hist)+len(b) > dictSize {
			continue
		}
		hist = append(hist, b...)
	}
	if len(samples) < 8 || len(hist) < 8 {
		return nil
	}
	dict, err := zstd.BuildDict(zstd.BuildDictOptions{Contents: samples, History: hist, ID: dictID})
	if err != nil {
		return nil
	}
	return dict
}

// textual reports whether b looks like text rather than an image or other
// already-compressed bytes. It samples the first 512 bytes and rejects the
// block if more than a few are non-text control characters.
func textual(b []byte) bool {
	n := len(b)
	if n > 512 {
		n = 512
	}
	bad := 0
	for _, c := range b[:n] {
		if c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			bad++
		}
	}
	return bad*50 < n
}

func encoder(dict []byte) (*zstd.Encoder, error) {
	if dict == nil {
		return zstd.NewWriter(nil)
	}
	return zstd.NewWriter(nil, zstd.WithEncoderDict(dict))
}

// Reader looks blocks up in an .opennet file.
type Reader struct {
	f       *os.File
	dec     *zstd.Decoder
	entries []entry
}

// Open opens an .opennet file for reading.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r := &Reader{f: f}
	if err := r.load(); err != nil {
		f.Close()
		return nil, err
	}
	return r, nil
}

func (r *Reader) load() error {
	var head [6]byte
	if _, err := io.ReadFull(r.f, head[:]); err != nil {
		return ErrFormat
	}
	if string(head[:4]) != magic {
		return ErrFormat
	}
	if head[4] != version {
		return ErrVersion
	}
	var dl [4]byte
	if _, err := io.ReadFull(r.f, dl[:]); err != nil {
		return ErrFormat
	}
	dict := make([]byte, binary.BigEndian.Uint32(dl[:]))
	if _, err := io.ReadFull(r.f, dict); err != nil {
		return ErrFormat
	}

	end, err := r.f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if end < 12 {
		return ErrFormat
	}
	var footer [12]byte
	if _, err := r.f.ReadAt(footer[:], end-12); err != nil {
		return err
	}
	if string(footer[8:]) != magic {
		return ErrFormat
	}
	indexAt := int64(binary.BigEndian.Uint64(footer[:8]))

	if _, err := r.f.Seek(indexAt, io.SeekStart); err != nil {
		return err
	}
	var count [4]byte
	if _, err := io.ReadFull(r.f, count[:]); err != nil {
		return ErrFormat
	}
	n := binary.BigEndian.Uint32(count[:])
	r.entries = make([]entry, n)
	for i := range r.entries {
		var rec [44]byte
		if _, err := io.ReadFull(r.f, rec[:]); err != nil {
			return ErrFormat
		}
		copy(r.entries[i].id[:], rec[:32])
		r.entries[i].offset = binary.BigEndian.Uint64(rec[32:40])
		r.entries[i].length = binary.BigEndian.Uint32(rec[40:])
	}

	if len(dict) == 0 {
		r.dec, err = zstd.NewReader(nil)
	} else {
		r.dec, err = zstd.NewReader(nil, zstd.WithDecoderDicts(dict))
	}
	return err
}

// Count is the number of blocks in the file.
func (r *Reader) Count() int { return len(r.entries) }

// Get returns the raw bytes of the block with the given CID. The bytes are
// hashed on the way out and rejected if they don't match, so a corrupted file
// can't silently hand back the wrong content.
func (r *Reader) Get(id cid.ID) ([]byte, error) {
	e, ok := r.find(id)
	if !ok {
		return nil, errNotFound
	}
	compressed := make([]byte, e.length)
	if _, err := r.f.ReadAt(compressed, int64(e.offset)); err != nil {
		return nil, err
	}
	raw, err := r.dec.DecodeAll(compressed, nil)
	if err != nil {
		return nil, err
	}
	if cid.Sum(raw) != id {
		return nil, errCorrupt
	}
	return raw, nil
}

var (
	errNotFound = errors.New("opennet: block not in file")
	errCorrupt  = errors.New("opennet: block does not match its CID")
)

func (r *Reader) find(id cid.ID) (entry, bool) {
	i := sort.Search(len(r.entries), func(i int) bool {
		return bytes.Compare(r.entries[i].id[:], id[:]) >= 0
	})
	if i < len(r.entries) && r.entries[i].id == id {
		return r.entries[i], true
	}
	return entry{}, false
}

// Close releases the file.
func (r *Reader) Close() error {
	if r.dec != nil {
		r.dec.Close()
	}
	return r.f.Close()
}
