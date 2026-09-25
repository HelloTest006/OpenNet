package container

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"opennet/internal/cid"
)

func TestRoundTrip(t *testing.T) {
	w := NewWriter()
	page := []byte("<html><body><h1>hello</h1><p>a page</p></body></html>")
	shared := bytes.Repeat([]byte("body{margin:0;font:16px sans-serif}"), 20)

	pageID := w.Add(page)
	sharedID := w.Add(shared)
	again := w.Add(shared)
	if again != sharedID {
		t.Fatal("identical bytes got different CIDs")
	}
	if w.Count() != 2 {
		t.Fatalf("dedup failed: %d blocks stored for 2 distinct", w.Count())
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "slice.opennet")
	if _, err := w.WriteFile(path); err != nil {
		t.Fatal(err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if r.Count() != 2 {
		t.Fatalf("count = %d", r.Count())
	}
	got, err := r.Get(pageID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, page) {
		t.Fatalf("page mismatch: %q", got)
	}
	got, err = r.Get(sharedID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, shared) {
		t.Fatal("shared asset mismatch")
	}
	if _, err := r.Get(cid.Sum([]byte("absent"))); err == nil {
		t.Fatal("missing block returned data")
	}
}

func TestCorruptBlockRejected(t *testing.T) {
	w := NewWriter()
	id := w.Add([]byte("honest content that is long enough to matter"))

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.opennet")
	if _, err := w.WriteFile(path); err != nil {
		t.Fatal(err)
	}

	// Flip a byte in the compressed region. Decompression either fails outright
	// or yields bytes that no longer hash to the CID; both must surface.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := f.Stat()
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, info.Size()/2); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xff
	if _, err := f.WriteAt(b, info.Size()/2); err != nil {
		t.Fatal(err)
	}
	f.Close()

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Get(id); err == nil {
		t.Fatal("corrupted block accepted")
	}
}

func TestNotOpenNet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nope.opennet")
	os.WriteFile(path, []byte("this is not the format"), 0o644)
	if _, err := Open(path); err != ErrFormat {
		t.Fatalf("got %v", err)
	}
}

// TestCorpusYield measures what the format actually achieves on a corpus of
// many small, template-similar sites, which is the case shared-dictionary
// compression is for. It prints the bytes per site so the capacity claim stays
// a measurement rather than a guess.
func TestCorpusYield(t *testing.T) {
	const sites = 2000
	w := NewWriter()

	style := []byte("<style>body{margin:0;font-family:sans-serif;background:#fff;color:#222}" +
		"header{padding:1rem;border-bottom:1px solid #ddd}article{max-width:40rem;margin:auto}" +
		"h1{font-size:1.6rem}p{line-height:1.5}</style>")
	nav := []byte("<nav><a href='/'>home</a><a href='/about'>about</a><a href='/archive'>archive</a></nav>")
	w.Add(style)
	w.Add(nav)

	var raw int
	for i := 0; i < sites; i++ {
		page := []byte(fmt.Sprintf("<!doctype html><html><head><title>Site %d</title></head><body>"+
			"<header><h1>Site %d</h1></header><article>"+
			"<p>This is site number %d in the corpus, a small static page that shares its "+
			"layout, navigation, and styling with every other site here.</p>"+
			"<p>The useful content is the part that differs, and there is not much of it.</p>"+
			"</article></body></html>", i, i, i))
		raw += len(page) + len(style) + len(nav)
		w.Add(page)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "corpus.opennet")
	n, err := w.WriteFile(path)
	if err != nil {
		t.Fatal(err)
	}

	perSite := float64(n) / float64(sites)
	t.Logf("%d sites, %d distinct blocks", sites, w.Count())
	t.Logf("raw bytes referenced: %d", raw)
	t.Logf("file bytes:           %d (%.0f bytes/site, %.1fx over raw)", n, perSite, float64(raw)/float64(n))

	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	sample := []byte(fmt.Sprintf("<!doctype html><html><head><title>Site %d</title>", 1234))
	// Rebuild the exact page to confirm random access still returns intact bytes.
	page := []byte(fmt.Sprintf("<!doctype html><html><head><title>Site %d</title></head><body>"+
		"<header><h1>Site %d</h1></header><article>"+
		"<p>This is site number %d in the corpus, a small static page that shares its "+
		"layout, navigation, and styling with every other site here.</p>"+
		"<p>The useful content is the part that differs, and there is not much of it.</p>"+
		"</article></body></html>", 1234, 1234, 1234))
	got, err := r.Get(cid.Sum(page))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, page) {
		t.Fatal("random access returned altered bytes")
	}
	_ = sample
}
