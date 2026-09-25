// Package crawl mirrors sites from OpenNet peers into an .opennet corpus.
//
// A crawl starts from the sites a node asks for by name. For each one it
// fetches the signed manifest, checks the signature, fetches every block the
// manifest names, and stores the blocks keyed by their content ID. A page that
// references opennet:<name> names another site, and those are followed
// breadth-first until the corpus reaches the limits it was given. A site's own
// blocks all come from its manifest, so a CID written inside a page is not
// followed on its own.
//
// Nothing is trusted on the way in. A block is kept only when its bytes hash to
// the CID it was requested under, and a manifest is kept only when its
// publisher's signature verifies, so a peer can withhold a site but cannot hand
// back a modified one. The same bytes are stored once no matter how many sites
// reference them, because the corpus is content addressed.
package crawl

import (
	"errors"
	"regexp"

	"opennet/internal/cid"
	"opennet/internal/container"
	"opennet/internal/frame"
	"opennet/internal/manifest"
	"opennet/internal/session"
)

// Default limits bound a crawl that would otherwise follow links forever or
// hold an unbounded amount of someone else's content.
const (
	// DefaultMaxSites is how many sites one crawl will mirror.
	DefaultMaxSites = 1000
	// DefaultMaxBytes is how much raw content one crawl will hold.
	DefaultMaxBytes = 500 << 20
	// DefaultMaxDepth is how many links away from the seeds a crawl will follow.
	DefaultMaxDepth = 4
	// DefaultMaxAsset is the largest single block a crawl will keep. Anything
	// bigger is almost always accidental, and one block must stay well under the
	// frame size limit.
	DefaultMaxAsset = 4 << 20
)

// Peer is the part of a session a crawl needs: asking for a site by name and
// fetching the blocks its manifest names. *session.Conn implements it.
type Peer interface {
	FetchSite(name string) ([]byte, error)
	FetchBlocks(ids []cid.ID) (map[cid.ID][]byte, error)
}

// Options bounds a crawl. Zero values select the defaults.
type Options struct {
	// Seeds are the site names the crawl starts from.
	Seeds []string
	// MaxSites, MaxBytes, MaxDepth, and MaxAsset override the defaults when set.
	MaxSites int
	MaxBytes int64
	MaxDepth int
	MaxAsset int
}

// Result is what a crawl produced.
type Result struct {
	// Sites are the manifests that were mirrored, in the order they were found.
	Sites []frame.Manifest
	// Blocks maps a CID to its raw bytes, across every site mirrored.
	Blocks map[cid.ID][]byte
	// Skipped counts sites that were named but not mirrored: the peer did not
	// carry them, the signature failed, or they would have broken a limit.
	Skipped int
	// Truncated reports that the crawl stopped because it hit a limit rather
	// than because it ran out of links to follow.
	Truncated bool
}

// Corpus mirrors sites from peer, starting at opts.Seeds and following the
// links it finds, and returns everything it kept.
func Corpus(peer Peer, opts Options) (Result, error) {
	c := &crawler{
		peer:     peer,
		maxSites: or(opts.MaxSites, DefaultMaxSites),
		maxBytes: or64(opts.MaxBytes, DefaultMaxBytes),
		maxDepth: or(opts.MaxDepth, DefaultMaxDepth),
		maxAsset: or(opts.MaxAsset, DefaultMaxAsset),
		blocks:   map[cid.ID][]byte{},
		seen:     map[string]int{},
	}
	for _, name := range opts.Seeds {
		c.enqueue(name, 0)
	}
	for c.next < len(c.queue) {
		item := c.queue[c.next]
		c.next++
		if err := c.take(item); err != nil {
			return Result{}, err
		}
	}
	return Result{Sites: c.sites, Blocks: c.blocks, Skipped: c.skipped, Truncated: c.truncated}, nil
}

// Write adds res to w, manifest bytes included, so the corpus is readable back
// without a separate index. Each manifest is stored under its own CID like any
// other block; res.Sites says which blocks are manifests and what they name.
func Write(w *container.Writer, res Result) {
	for _, m := range res.Sites {
		w.Add(m.Marshal())
	}
	for _, b := range res.Blocks {
		w.Add(b)
	}
}

type item struct {
	name  string
	depth int
}

type crawler struct {
	peer                         Peer
	maxSites, maxDepth, maxAsset int
	maxBytes                     int64

	queue        []item
	next         int
	seen         map[string]int
	sites        []frame.Manifest
	blocks       map[cid.ID][]byte
	used         int64
	skipped      int
	truncated    bool
	pendingBytes int64
	pending      map[cid.ID][]byte
}

func (c *crawler) enqueue(name string, depth int) {
	if depth > c.maxDepth {
		return
	}
	if at, ok := c.seen[name]; ok {
		// A shorter path to a site already queued is worth taking, because it
		// leaves more depth budget for whatever that site links to.
		if depth < at && at <= c.maxDepth {
			c.seen[name] = depth
			c.queue = append(c.queue, item{name, depth})
		}
		return
	}
	c.seen[name] = depth
	c.queue = append(c.queue, item{name, depth})
}

func (c *crawler) take(it item) error {
	if c.seen[it.name] != it.depth {
		return nil // a shorter path superseded this one
	}
	if len(c.sites) >= c.maxSites {
		c.truncated = true
		return nil
	}

	raw, err := c.peer.FetchSite(it.name)
	if errors.Is(err, session.ErrNoSite) {
		// The peer answered and simply does not carry this site. That is a gap
		// in its slice, not a failure of the crawl.
		c.skipped++
		return nil
	}
	if err != nil {
		return err
	}
	m, err := frame.UnmarshalManifest(raw)
	if err != nil || manifest.Verify(m) != nil || m.Name != it.name {
		// A manifest that claims a different name than the one asked for is a
		// peer answering the wrong question, and is treated like a bad signature.
		c.skipped++
		return nil
	}

	want := make([]cid.ID, 0, len(m.Blocks))
	for _, id := range m.Blocks {
		if _, ok := c.blocks[id]; !ok {
			want = append(want, id)
		}
	}
	got := map[cid.ID][]byte{}
	if len(want) > 0 {
		got, err = c.peer.FetchBlocks(want)
		if err != nil {
			return err
		}
	}

	c.pending = map[cid.ID][]byte{}
	c.pendingBytes = 0
	ok := true
	for _, id := range m.Blocks {
		b, held := c.blocks[id]
		if !held {
			b, held = got[id]
		}
		if !held || len(b) > c.maxAsset || c.used+c.pendingBytes+int64(len(b)) > c.maxBytes {
			ok = false
			break
		}
		if _, seen := c.pending[id]; !seen && !c.held(id) {
			c.pending[id] = b
			c.pendingBytes += int64(len(b))
		}
	}
	if !ok {
		c.skipped++
		c.truncated = true
		return nil
	}
	for id, b := range c.pending {
		c.blocks[id] = b
		c.used += int64(len(b))
	}
	c.sites = append(c.sites, m)

	for _, id := range m.Blocks {
		for _, name := range siteRefs(c.blocks[id]) {
			c.enqueue(name, it.depth+1)
		}
	}
	return nil
}

func (c *crawler) held(id cid.ID) bool {
	_, ok := c.blocks[id]
	return ok
}

// siteRef matches an opennet: link. The scheme is deliberate so a crawl never
// confuses a reference to another OpenNet site with an ordinary web URL that
// happens to appear in the same page. Names are restricted to the characters
// that can occur in one, so markup around the link ends it.
var siteRef = regexp.MustCompile(`opennet:([A-Za-z0-9._~-]{1,200})`)

// blockRef matches a CID written out as 64 hex characters, which is how a page
// points at another of its own blocks.
var blockRef = regexp.MustCompile(`[0-9a-f]{64}`)

// siteRefs returns the names of other OpenNet sites referenced in a block.
func siteRefs(b []byte) []string {
	found := siteRef.FindAllSubmatch(b, -1)
	out := make([]string, 0, len(found))
	for _, m := range found {
		out = append(out, string(m[1]))
	}
	return out
}

// blockRefs returns the block IDs referenced in a block. It is exported for
// callers that want to follow intra-site links themselves; Corpus follows site
// links only, because a site's own blocks are fetched whole from its manifest.
func BlockRefs(b []byte) []cid.ID {
	found := blockRef.FindAll(b, -1)
	var out []cid.ID
	for _, m := range found {
		id, err := cid.Parse(string(m))
		if err != nil || id.IsZero() {
			continue
		}
		out = append(out, id)
	}
	return out
}

func or(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func or64(v, def int64) int64 {
	if v == 0 {
		return def
	}
	return v
}
