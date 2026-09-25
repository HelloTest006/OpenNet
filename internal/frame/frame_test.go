package frame

import (
	"bytes"
	"testing"

	"opennet/internal/cid"
)

func TestRoundTrip(t *testing.T) {
	c1, c2 := cid.Sum([]byte("a")), cid.Sum([]byte("b"))
	frames := []Frame{
		{TypeHello, Hello{NodeID: []byte("node"), Cert: []byte("cert"), Links: []string{"tcp", "wifi"}}.Marshal()},
		{TypeHave, Have{CIDs: []cid.ID{c1, c2}}.Marshal()},
		{TypeWant, Want{CIDs: []cid.ID{c1}}.Marshal()},
		{TypeBlock, Block{CID: c1, Data: []byte("hello")}.Marshal()},
		{TypeResolve, Resolve{Name: "news"}.Marshal()},
		{TypeManifest, Manifest{Name: "news", PubKey: []byte("pk"), Entry: c1, Blocks: []cid.ID{c1, c2}, Sig: []byte("sig")}.Marshal()},
	}

	var buf bytes.Buffer
	for _, f := range frames {
		if err := Write(&buf, f); err != nil {
			t.Fatal(err)
		}
	}
	for i, want := range frames {
		got, err := Read(&buf)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if got.Type != want.Type || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("frame %d mismatch", i)
		}
	}
}

func TestManifestFields(t *testing.T) {
	c := cid.Sum([]byte("page"))
	m := Manifest{Name: "docs", PubKey: []byte{1, 2, 3}, Entry: c, Blocks: []cid.ID{c}, Sig: []byte("sig")}
	back, err := UnmarshalManifest(m.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if back.Name != m.Name || !bytes.Equal(back.PubKey, m.PubKey) || back.Entry != c || len(back.Blocks) != 1 || back.Blocks[0] != c {
		t.Fatalf("manifest mismatch: %+v", back)
	}
}

func TestTruncated(t *testing.T) {
	if _, err := UnmarshalHello([]byte{0, 0, 0, 5, 1, 2}); err == nil {
		t.Fatal("truncated hello accepted")
	}
}

func TestTooLarge(t *testing.T) {
	f := Frame{Type: TypeBlock, Payload: make([]byte, maxPayload)}
	if err := Write(&bytes.Buffer{}, f); err != ErrTooLarge {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
}
