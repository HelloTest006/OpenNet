package session

import (
	"bytes"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"opennet/internal/cid"
	"opennet/internal/frame"
	"opennet/internal/member"
	"opennet/internal/store"
)

func pipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	a, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestExchange(t *testing.T) {
	page := []byte("<h1>hello opennet</h1>")
	id := cid.Sum(page)

	held := store.NewMem()
	held.Put(page)
	pub := frame.Manifest{Name: "news", PubKey: []byte("publisher"), Entry: id, Blocks: []cid.ID{id}, Sig: []byte("sig")}

	server := &Node{PubKey: []byte("server-key"), Cert: []byte("community-cert"), Links: []string{"tcp", "wifi"},
		Store: held, Sites: map[string][]byte{"news": pub.Marshal()}}
	client := &Node{PubKey: []byte("client-key"), Store: store.NewMem(), Sites: map[string][]byte{}}

	sc, cc := pipe(t)

	errc := make(chan error, 1)
	var srv *Conn
	go func() {
		var err error
		srv, err = server.Handshake(sc)
		if err != nil {
			errc <- err
			return
		}
		errc <- srv.Serve()
	}()

	cli, err := client.Handshake(cc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cli.Peer.NodeID, server.PubKey) {
		t.Fatalf("peer id = %q", cli.Peer.NodeID)
	}
	if got := cli.Peer.Links; len(got) != 2 || got[0] != "tcp" || got[1] != "wifi" {
		t.Fatalf("links = %v", got)
	}

	raw, err := cli.FetchSite("news")
	if err != nil {
		t.Fatal(err)
	}
	m, err := frame.UnmarshalManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "news" || m.Entry != id {
		t.Fatalf("manifest = %+v", m)
	}

	blocks, err := cli.FetchBlocks(m.Blocks)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blocks[id], page) {
		t.Fatalf("block = %q", blocks[id])
	}

	if _, err := cli.FetchSite("missing"); err != ErrNoSite {
		t.Fatalf("missing site: got %v", err)
	}

	cc.Close()
	<-errc
}

func TestMembershipEnforced(t *testing.T) {
	ca, err := member.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	other, err := member.NewAuthority()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_000_000, 0)

	memberNode := &Node{Store: store.NewMem(), Sites: map[string][]byte{}, Now: func() time.Time { return now }}
	if err := memberNode.identify(ca, now); err != nil {
		t.Fatal(err)
	}

	// A private network trusts only its own authority.
	private := &Node{Store: store.NewMem(), Sites: map[string][]byte{},
		Trust: []ed25519.PublicKey{ca.Public}, Now: func() time.Time { return now }}
	if err := private.identify(ca, now); err != nil {
		t.Fatal(err)
	}

	sc, cc := pipe(t)
	go func() { private.Handshake(sc) }()
	if _, err := memberNode.Handshake(cc); err != nil {
		t.Fatalf("valid member rejected: %v", err)
	}

	outsider := &Node{Store: store.NewMem(), Sites: map[string][]byte{}, Now: func() time.Time { return now }}
	if err := outsider.identify(other, now); err != nil {
		t.Fatal(err)
	}
	sc, cc = pipe(t)
	got := make(chan error, 1)
	go func() {
		_, err := outsider.Handshake(sc)
		got <- err
	}()
	if _, err := private.Handshake(cc); err != ErrRejected {
		t.Fatalf("private node accepted a foreign certificate: got %v", err)
	}
	<-got

	expired := &Node{Store: store.NewMem(), Sites: map[string][]byte{}, Now: func() time.Time { return now }}
	if err := expired.identify(ca, now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	sc, cc = pipe(t)
	go func() {
		expired.Handshake(sc)
	}()
	if _, err := private.Handshake(cc); err != ErrRejected {
		t.Fatalf("expired certificate: got %v", err)
	}
}

// identify gives n a fresh identity and a certificate from ca issued at at.
func (n *Node) identify(ca member.Authority, at time.Time) error {
	id, err := member.NewIdentity()
	if err != nil {
		return err
	}
	cert, err := ca.Issue(id.Public, at.Add(-time.Hour), at.Add(time.Hour))
	if err != nil {
		return err
	}
	n.PubKey = id.Public
	n.Cert = cert.Marshal()
	return nil
}

func TestBadBlockRejected(t *testing.T) {
	sc, cc := pipe(t)
	defer sc.Close()
	defer cc.Close()

	go func() {
		frame.Write(sc, frame.Frame{Type: frame.TypeHello, Payload: frame.Hello{NodeID: []byte("p")}.Marshal()})
		frame.Read(sc) // client's hello
		frame.Read(sc) // client's want
		claimed := cid.Sum([]byte("honest"))
		frame.Write(sc, frame.Frame{Type: frame.TypeBlock, Payload: frame.Block{CID: claimed, Data: []byte("tampered")}.Marshal()})
	}()

	n := &Node{PubKey: []byte("c"), Store: store.NewMem()}
	c, err := n.Handshake(cc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.FetchBlocks([]cid.ID{cid.Sum([]byte("honest"))}); err != ErrBadBlock {
		t.Fatalf("got %v, want ErrBadBlock", err)
	}
}
