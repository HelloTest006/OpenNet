// Command opennetd is a node in the OpenNet.
//
// A node holds a slice of the corpus and serves it to peers that connect. It
// speaks TCP here, which is enough to prove the protocol between two processes
// on one machine; the Wi-Fi Direct and custom-radio links implement the same
// transport interface and need no change here.
//
// Membership is optional and keyed off -trust. With no authority given, a node
// accepts anyone, which suits trying the protocol out. With one, it accepts
// only peers carrying a certificate from that authority that is still inside
// its validity window:
//
//	opennetd authority -out community.authority
//	opennetd identity  -authority community.authority -out node.identity
//	opennetd serve     -listen 127.0.0.1:9731 -identity node.identity -trust community.authority
//	opennetd fetch     -peer 127.0.0.1:9731 -identity node.identity -trust community.authority -name news
//
// A private network is the same commands with an authority key that is not
// shared. Whoever does not hold a certificate from it cannot complete a
// handshake.
//
//	opennetd pack -out slice.opennet page.html style.css
package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"opennet/internal/cid"
	"opennet/internal/container"
	"opennet/internal/frame"
	"opennet/internal/manifest"
	"opennet/internal/member"
	"opennet/internal/session"
	"opennet/internal/store"
	"opennet/internal/transport"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "authority":
		authority(os.Args[2:])
	case "identity":
		identity(os.Args[2:])
	case "serve":
		serve(os.Args[2:])
	case "fetch":
		fetch(os.Args[2:])
	case "pack":
		pack(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: opennetd authority|identity|serve|fetch|pack [flags]")
	os.Exit(2)
}

const (
	day = 24 * time.Hour
	// certLife is how long an issued certificate stays valid. Short on purpose:
	// expiry is the revocation mechanism, so a leaked certificate dies on its own.
	certLife = 14 * day
)

func authority(args []string) {
	fs := flag.NewFlagSet("authority", flag.ExitOnError)
	out := fs.String("out", "community.authority", "file to write the authority key to")
	fs.Parse(args)

	a, err := member.NewAuthority()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, a.Private(), 0o600); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s", *out)
	log.Printf("distribute this public key to every node that should trust it:\n%x", a.Public)
}

func identity(args []string) {
	fs := flag.NewFlagSet("identity", flag.ExitOnError)
	auth := fs.String("authority", "", "authority key to sign the certificate with")
	out := fs.String("out", "node.identity", "file to write the identity to")
	life := fs.Duration("life", certLife, "how long the certificate stays valid")
	fs.Parse(args)
	if *auth == "" {
		log.Fatal("identity: -authority is required")
	}

	a, err := loadAuthority(*auth)
	if err != nil {
		log.Fatal(err)
	}
	id, err := member.NewIdentity()
	if err != nil {
		log.Fatal(err)
	}
	cert, err := a.Issue(id.Public, time.Now().Add(-time.Minute), time.Now().Add(*life))
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, append(id.Private(), cert.Marshal()...), 0o600); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s, valid for %s", *out, life.String())
}

// loadNode reads an identity file into a session node. An empty path gives a
// node with a fresh, uncertified identity, which can only talk to peers that
// are not checking membership.
func loadNode(path string, trust []ed25519.PublicKey) *session.Node {
	n := &session.Node{Links: []string{"tcp", "wifi"}, Store: store.NewMem(), Sites: map[string][]byte{}, Trust: trust}
	if path == "" {
		id, err := member.NewIdentity()
		if err != nil {
			log.Fatal(err)
		}
		n.PubKey = id.Public
		n.Signer = id
		return n
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	id, cert, err := member.ParseIdentity(raw)
	if err != nil {
		log.Fatal(err)
	}
	n.PubKey = id.Public
	n.Signer = id
	n.Cert = cert
	return n
}

// loadTrust reads authority files and returns their public keys. An empty list
// means the node checks nothing.
func loadTrust(paths []string) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, p := range paths {
		if p == "" {
			continue
		}
		a, err := loadAuthority(p)
		if err != nil {
			log.Fatal(err)
		}
		out = append(out, a.Public)
	}
	return out
}

func loadAuthority(path string) (member.Authority, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return member.Authority{}, err
	}
	return member.AuthorityFrom(raw)
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:9731", "address to serve on")
	name := fs.String("name", "", "site name to publish")
	page := fs.String("page", "", "file to publish as the site's single page")
	ident := fs.String("identity", "", "identity file; a fresh uncertified one is used if empty")
	trust := fs.String("trust", "", "comma-separated authority files whose members are admitted")
	fs.Parse(args)

	node := loadNode(*ident, loadTrust(split(*trust)))

	if *name != "" && *page != "" {
		data, err := os.ReadFile(*page)
		if err != nil {
			log.Fatal(err)
		}
		id := node.Store.Put(data)
		m := frame.Manifest{Name: *name, Entry: id, Blocks: []cid.ID{id}}
		manifest.Sign(&m, node.Signer)
		node.Sites[*name] = m.Marshal()
		log.Printf("publishing %q (%d bytes)", *name, len(data))
	}

	ln, err := transport.TCP{}.Listen(*listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("serving on %s", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handle(node, c)
	}
}

func handle(node *session.Node, c transport.Conn) {
	defer c.Close()
	sess, err := node.Handshake(c)
	if err != nil {
		log.Printf("rejected %s: %v", c.Remote(), err)
		return
	}
	log.Printf("peer %x connected from %s", sess.Peer.NodeID, c.Remote())
	if err := sess.Serve(); err != nil {
		log.Printf("peer %x: %v", sess.Peer.NodeID, err)
	}
}

func fetch(args []string) {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	peer := fs.String("peer", "127.0.0.1:9731", "node to fetch from")
	name := fs.String("name", "", "site name to fetch")
	out := fs.String("out", "", "file to write the entry page to (stdout if empty)")
	ident := fs.String("identity", "", "identity file; a fresh uncertified one is used if empty")
	trust := fs.String("trust", "", "comma-separated authority files whose members are admitted")
	fs.Parse(args)
	if *name == "" {
		log.Fatal("fetch: -name is required")
	}

	c, err := transport.TCP{}.Dial(*peer)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	node := loadNode(*ident, loadTrust(split(*trust)))
	sess, err := node.Handshake(c)
	if err != nil {
		log.Fatal(err)
	}

	raw, err := sess.FetchSite(*name)
	if err != nil {
		log.Fatal(err)
	}
	m, err := frame.UnmarshalManifest(raw)
	if err != nil {
		log.Fatal(err)
	}
	if err := manifest.Verify(m); err != nil {
		log.Fatalf("site %q: %v", *name, err)
	}
	blocks, err := sess.FetchBlocks(m.Blocks)
	if err != nil {
		log.Fatal(err)
	}

	page, ok := blocks[m.Entry]
	if !ok {
		log.Fatal("peer did not return the entry block")
	}
	if *out == "" {
		os.Stdout.Write(page)
		return
	}
	if err := os.WriteFile(*out, page, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s (%d bytes, %d blocks) signed by %x", *out, len(page), len(blocks), m.PubKey)
}

func pack(args []string) {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	out := fs.String("out", "slice.opennet", "file to write")
	fs.Parse(args)
	if fs.NArg() == 0 {
		log.Fatal("pack: give the files to include")
	}

	w := container.NewWriter()
	var raw int
	for _, path := range fs.Args() {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		w.Add(data)
		raw += len(data)
	}
	n, err := w.WriteFile(*out)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s: %d files, %d distinct blocks, %d bytes (%.0f%% of raw)",
		*out, fs.NArg(), w.Count(), n, pct(int(n), raw))
}

func pct(stored, raw int) float64 {
	if raw == 0 {
		return 0
	}
	return float64(stored) / float64(raw) * 100
}
