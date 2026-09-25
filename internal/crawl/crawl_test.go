package crawl

import (
	"errors"
	"testing"

	"opennet/internal/cid"
	"opennet/internal/container"
	"opennet/internal/frame"
	"opennet/internal/manifest"
	"opennet/internal/member"
	"opennet/internal/session"
)

// fake is a peer holding a fixed set of sites. It records what was asked for,
// and it can be told to lie about a block.
type fake struct {
	sites  map[string]frame.Manifest
	blocks map[cid.ID][]byte
	lie    map[cid.ID][]byte
	asked  []string
	fail   string
}

func (f *fake) FetchSite(name string) ([]byte, error) {
	f.asked = append(f.asked, name)
	if name == f.fail {
		return nil, errors.New("peer dropped the connection")
	}
	m, ok := f.sites[name]
	if !ok {
		return nil, session.ErrNoSite
	}
	return m.Marshal(), nil
}

func (f *fake) FetchBlocks(ids []cid.ID) (map[cid.ID][]byte, error) {
	out := make(map[cid.ID][]byte, len(ids))
	for _, id := range ids {
		if b, ok := f.lie[id]; ok {
			out[id] = b
			continue
		}
		b, ok := f.blocks[id]
		if !ok {
			return nil, errors.New("missing block")
		}
		out[id] = b
	}
	return out, nil
}

// net builds a small network. Each site's page links to the next, so a crawl
// seeded with the first reaches all of them, and the last links nowhere.
func net(t *testing.T, names []string, pub member.Identity) *fake {
	t.Helper()
	f := &fake{sites: map[string]frame.Manifest{}, blocks: map[cid.ID][]byte{}}
	for i, name := range names {
		body := "<h1>" + name + "</h1>"
		if i+1 < len(names) {
			body += `<a href="opennet:` + names[i+1] + `">next</a>`
		}
		page := []byte(body)
		id := cid.Sum(page)
		m := frame.Manifest{Name: name, Entry: id, Blocks: []cid.ID{id}}
		manifest.Sign(&m, pub)
		f.sites[name] = m
		f.blocks[id] = page
	}
	return f
}

func TestFollowsLinks(t *testing.T) {
	pub, err := member.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f := net(t, []string{"news", "sport", "weather"}, pub)

	res, err := Corpus(f, Options{Seeds: []string{"news"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sites) != 3 {
		t.Fatalf("mirrored %d sites, want 3", len(res.Sites))
	}
	got := map[string]bool{}
	for _, m := range res.Sites {
		got[m.Name] = true
		if manifest.Verify(m) != nil {
			t.Fatalf("%s: signature failed", m.Name)
		}
		if _, ok := res.Blocks[m.Entry]; !ok {
			t.Fatalf("%s: entry block missing", m.Name)
		}
	}
	for _, name := range []string{"news", "sport", "weather"} {
		if !got[name] {
			t.Fatalf("missing %s", name)
		}
	}
	if res.Skipped != 0 || res.Truncated {
		t.Fatalf("skipped %d, truncated %v", res.Skipped, res.Truncated)
	}
}

func TestDepthLimit(t *testing.T) {
	pub, err := member.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f := net(t, []string{"a", "b", "c", "d"}, pub)

	res, err := Corpus(f, Options{Seeds: []string{"a"}, MaxDepth: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sites) != 2 {
		t.Fatalf("mirrored %d sites, want the seed and one hop", len(res.Sites))
	}
	for _, asked := range f.asked {
		if asked == "c" || asked == "d" {
			t.Fatalf("fetched %s past the depth limit", asked)
		}
	}
}

func TestSiteCap(t *testing.T) {
	pub, err := member.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f := net(t, []string{"a", "b", "c"}, pub)

	res, err := Corpus(f, Options{Seeds: []string{"a"}, MaxSites: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sites) != 1 || !res.Truncated {
		t.Fatalf("sites %d, truncated %v", len(res.Sites), res.Truncated)
	}
}

func TestByteCap(t *testing.T) {
	pub, err := member.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f := net(t, []string{"a", "b"}, pub)

	res, err := Corpus(f, Options{Seeds: []string{"a"}, MaxBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	// The first site alone is bigger than the budget, so nothing is kept and the
	// crawl reports it stopped on a limit.
	if len(res.Sites) != 0 || !res.Truncated || res.Skipped != 1 {
		t.Fatalf("sites %d, skipped %d, truncated %v", len(res.Sites), res.Skipped, res.Truncated)
	}
	if len(res.Blocks) != 0 {
		t.Fatal("kept blocks from a site that broke the budget")
	}
}

func TestSharedBlockStoredOnce(t *testing.T) {
	pub, err := member.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	style := bytes64("body{margin:0}")
	id := cid.Sum(style)

	f := &fake{sites: map[string]frame.Manifest{}, blocks: map[cid.ID][]byte{id: style}}
	for _, name := range []string{"news", "sport"} {
		page := []byte("<h1>" + name + "</h1>")
		pid := cid.Sum(page)
		m := frame.Manifest{Name: name, Entry: pid, Blocks: []cid.ID{pid, id}}
		manifest.Sign(&m, pub)
		f.sites[name] = m
		f.blocks[pid] = page
	}

	res, err := Corpus(f, Options{Seeds: []string{"news", "sport"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sites) != 2 {
		t.Fatalf("sites %d", len(res.Sites))
	}
	if len(res.Blocks) != 3 {
		t.Fatalf("blocks %d, want 2 pages plus the shared style once", len(res.Blocks))
	}
}

func TestBadSignatureSkipped(t *testing.T) {
	pub, err := member.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f := net(t, []string{"news"}, pub)
	for name, m := range f.sites {
		m.Sig[0] ^= 0xff
		f.sites[name] = m
	}

	res, err := Corpus(f, Options{Seeds: []string{"news"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sites) != 0 || len(res.Blocks) != 0 || res.Skipped != 1 {
		t.Fatalf("sites %d blocks %d skipped %d", len(res.Sites), len(res.Blocks), res.Skipped)
	}
}

func TestWrongNameSkipped(t *testing.T) {
	pub, err := member.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f := net(t, []string{"news"}, pub)

	// The peer answers a request for "other" with the "news" manifest.
	res, err := Corpus(&alias{f, "other", "news"}, Options{Seeds: []string{"other"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sites) != 0 || res.Skipped != 1 {
		t.Fatalf("sites %d skipped %d", len(res.Sites), res.Skipped)
	}
}

// alias serves from's manifest for to under a different requested name.
type alias struct {
	*fake
	to, from string
}

func (a *alias) FetchSite(name string) ([]byte, error) {
	if name == a.to {
		name = a.from
	}
	return a.fake.FetchSite(name)
}

func TestMissingSiteSkipped(t *testing.T) {
	pub, err := member.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f := net(t, []string{"news"}, pub)

	res, err := Corpus(f, Options{Seeds: []string{"news", "absent"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sites) != 1 || res.Skipped != 1 {
		t.Fatalf("sites %d skipped %d", len(res.Sites), res.Skipped)
	}
}

func TestTransportErrorPropagates(t *testing.T) {
	pub, err := member.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f := net(t, []string{"news"}, pub)
	f.fail = "news"

	if _, err := Corpus(f, Options{Seeds: []string{"news"}}); err == nil {
		t.Fatal("a dropped connection was swallowed")
	}
}

func TestWritesReadableCorpus(t *testing.T) {
	pub, err := member.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f := net(t, []string{"news", "sport"}, pub)
	res, err := Corpus(f, Options{Seeds: []string{"news"}})
	if err != nil {
		t.Fatal(err)
	}

	w := container.NewWriter()
	Write(w, res)
	path := t.TempDir() + "/slice.opennet"
	if _, err := w.WriteFile(path); err != nil {
		t.Fatal(err)
	}

	r, err := container.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	for _, m := range res.Sites {
		raw, err := r.Get(cid.Sum(m.Marshal()))
		if err != nil {
			t.Fatalf("%s manifest: %v", m.Name, err)
		}
		back, err := frame.UnmarshalManifest(raw)
		if err != nil {
			t.Fatal(err)
		}
		if manifest.Verify(back) != nil || back.Name != m.Name {
			t.Fatalf("%s did not round-trip", m.Name)
		}
		page, err := r.Get(m.Entry)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			t.Fatalf("%s page empty", m.Name)
		}
	}
}

func TestBlockRefs(t *testing.T) {
	id := cid.Sum([]byte("somewhere"))
	page := []byte("see " + id.String() + " for more, and not-a-cid")
	got := BlockRefs(page)
	if len(got) != 1 || got[0] != id {
		t.Fatalf("refs = %v", got)
	}
}

// bytes64 pads s so the tests read as content rather than construction.
func bytes64(s string) []byte { return []byte(s) }
