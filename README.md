# OpenNet

OpenNet is a peer-to-peer web whose nodes are ordinary devices. Each node holds
a slice of a corpus of sites and serves it directly to the peers that connect
to it, so there is no central server keeping the index and no operator the
network depends on. A site is a set of content-addressed blocks plus a signed
manifest, and any node that holds the blocks can hand them out; the signature
means a node can relay a site it did not publish without being able to alter
it.

This repository is the protocol and the node that speaks it, `opennetd`. The
link it runs on today is plain TCP, which is enough to run a network between
machines that can already reach each other. Two further links are part of the
design and have interfaces in the tree but no driver yet: a standard Wi-Fi link
that uses ordinary 802.11 frames, so it runs on any phone or laptop with no
extra hardware, and a custom-radio link for nodes built with a dedicated radio
module, which is the only way to send anything other than 802.11 frames. A
stock Wi-Fi chip speaks 802.11 and nothing else, so arbitrary waveforms are not
available on a handset. Peers advertise which links they have and use the one
they share.

## Install

Grab the binary for your machine from the
[releases](https://github.com/HelloTest006/OpenNet/releases) page. Nothing else
is needed; the binary is statically linked and has no dependencies.

| File | Runs on |
| --- | --- |
| `opennetd-linux-amd64` | Linux on x86-64: PCs and servers |
| `opennetd-linux-arm64` | Linux on 64-bit ARM: Raspberry Pi 3, 4, and 5 |
| `opennetd-linux-arm-v7` | Linux on 32-bit ARM: older boards |
| `opennetd-windows-amd64.exe` | Windows on x86-64 |
| `opennetd-windows-arm64.exe` | Windows on ARM |
| `opennetd-darwin-amd64` | macOS on Intel |
| `opennetd-darwin-arm64` | macOS on Apple silicon |
| `opennetd-freebsd-amd64` | FreeBSD on x86-64 |
| `opennetd-android-arm64` | Android phones, under [Termux](https://termux.dev) |

On Linux and macOS the downloaded file needs to be marked executable:

```
chmod +x opennetd-linux-amd64
./opennetd-linux-amd64
```

On Windows, run `opennetd-windows-amd64.exe` from a terminal. Windows Defender
SmartScreen warns about unsigned binaries downloaded from the internet; the
build is reproducible from this repository if you would rather compile it
yourself.

There is no `.apk`. A phone app would need an Android SDK, a manifest, and a
signing key, none of which this repository has, and it would do nothing the
binary doesn't until the Wi-Fi driver exists. The Android build runs as-is
inside Termux, which covers phones from roughly the last decade. There is no
32-bit Android build either: Go will not link that target without cgo, and
carrying an NDK cross-compiler in CI for phones that predate 2017 is not worth
it. The `linux-arm-v7` build covers old ARM boards.

To build from source instead, install [Go](https://go.dev/dl/) and run:

```
go build -o opennetd ./cmd/opennetd
```

The module is pure Go with cgo disabled, so cross-compiling is two environment
variables and nothing more:

```
GOOS=linux   GOARCH=arm64 go build -o opennetd ./cmd/opennetd
GOOS=android GOARCH=arm64 go build -o opennetd ./cmd/opennetd
```

`go test ./...` runs the suite. It covers the frame codec, content addressing,
the handshake with membership enforced, signed manifests, block transfer that
rejects a block whose bytes don't match its ID, and the `.opennet` container
including a corpus-size benchmark.

## Usage

`opennetd` has five subcommands.

```
opennetd authority   create a certificate authority
opennetd identity    create a node identity and its certificate
opennetd serve       serve a site to peers
opennetd fetch       fetch a site from a peer
opennetd pack        pack files into an .opennet corpus
```

Run any of them with `-h` to see its flags.

### Try it with no membership

The fastest way to see the protocol work is to skip certificates entirely. A
node started without `-trust` accepts anyone, and one started without
`-identity` invents a fresh identity for that run. This is fine for two
processes on your own machine and a bad idea for anything reachable by
strangers, since it gives away the only check the node has.

In one terminal, serve a page:

```
echo '<h1>hello from the node</h1>' > index.html
opennetd serve -listen 127.0.0.1:9731 -name news -page index.html
```

`serve` runs until you stop it. `-listen` defaults to `127.0.0.1:9731`, `-name`
is the site name peers ask for, and `-page` is the file published as that
site's page. Both `-name` and `-page` are optional; without them the node
serves but publishes nothing.

In a second terminal, fetch it:

```
opennetd fetch -peer 127.0.0.1:9731 -name news -out news.html
```

`-peer` defaults to `127.0.0.1:9731`. Without `-out` the page is written to
stdout, which is handy for piping it somewhere. The command prints the number
of bytes, the number of blocks, and the publisher's key, and it refuses to
write the file if the publisher's signature does not check out.

### Run a network with membership

Membership is what turns the above into a network rather than an open relay. A
certificate authority signs a certificate that says a particular node key is a
member until a particular time, and a node only completes a handshake with a
peer whose certificate it can verify. The check has three parts: the
certificate must be signed by an authority the node trusts, it must be inside
its validity window, and it must name the exact key the peer claims to be. The
third part matters because otherwise any member could replay any other member's
certificate.

One person creates the authority and keeps the file private. It is written with
mode 0600, and the public key is printed so it can be distributed:

```
opennetd authority -out community.authority
```

Every node then gets its own identity, signed by that authority:

```
opennetd identity -authority community.authority -out node.identity
```

The certificate lasts 14 days by default. Change it with `-life 72h`; the value
is a Go duration, so `720h` is thirty days and `90m` is ninety minutes. The
default is short on purpose. There is no revocation list, because distributing
one to every node is its own synchronization problem, and a certificate that
expires is a certificate that revokes itself. A node that should stay a member
gets a new certificate before the old one lapses, and a leaked one stops
working on its own.

Serve and fetch the same way as before, naming the identity and the authority:

```
opennetd serve -listen 0.0.0.0:9731 -identity node.identity -trust community.authority -name news -page index.html
opennetd fetch -peer 192.168.1.20:9731 -identity node.identity -trust community.authority -name news -out news.html
```

`-trust` takes a comma-separated list, so a node can belong to more than one
network at once:

```
opennetd serve -identity node.identity -trust community.authority,neighbors.authority
```

A peer that presents no certificate, a certificate from an authority not in
that list, an expired certificate, or a certificate issued to a different key
is dropped during the handshake, before any block is transferred. The serving
node logs the rejection with the reason.

### Run a private network

A private network uses exactly the same commands. The only difference is that
the authority file is never shared, so nobody outside the group can produce a
certificate that passes the check. Create the authority, issue an identity to
each member, and have every node pass that authority to `-trust`. Outsiders are
rejected at the handshake the same way a bad certificate is.

Treat the authority file as the network's root secret. Anyone who copies it can
issue memberships, and there is no way to undo one short of waiting for expiry
or switching the whole network to a new authority. Identity files are secrets
too: they contain the node's private key, and possession of one is possession
of that node.

### Pack a corpus

`pack` writes a set of files into one `.opennet` file, which is the format a
node uses to keep its slice of the corpus on disk:

```
opennetd pack -out slice.opennet index.html style.css app.js photo.jpg
```

`-out` defaults to `slice.opennet`. The command reports how many files went in,
how many distinct blocks came out, and the file's size as a percentage of the
raw input. The count of blocks can be lower than the count of files because
identical content is stored once, so repeating an asset across many pages costs
nothing the second time.

On a test corpus of 2,000 small pages that all shared one template, the result
was about 160 bytes per site, roughly four times smaller than the raw pages.
Read that number for what it measures: pages that share nearly all of their
bytes. A page of original writing compresses far less, and images barely
compress at all, so a corpus of real sites costs far more per site. A 500 MB
file holds thousands to a few tens of thousands of small static sites, not
millions, and the corpus gets bigger by more nodes holding more slices rather
than by compressing harder.

The file is random access. A block is retrieved by a binary search over the
index and a single read at the offset it points to, so a node can serve one
block out of a large corpus without unpacking any of it.

## How it works

### Content addressing

Every block is named by the BLAKE3 hash of its raw bytes, and that hash is the
only name it has. When a block arrives, the receiver hashes the bytes and drops
the block if the result differs from the ID it was requested under. That is
what makes relaying safe: a node in the middle can fail to forward a block, but
it cannot swap in a different one, because the recipient would notice. The node
publishing a block does not get to choose its ID.

### Sites and signatures

A site is a manifest naming the site, the publisher's public key, the block
that is the entry page, the full list of blocks, and an ed25519 signature over
all of it. `serve` signs the manifest with the node's identity as it publishes,
and `fetch` verifies the signature before it writes anything. Changing the
name, adding a block, or substituting a different publisher's key all make the
signature fail, so a site can pass through any number of nodes and arrive
intact or not at all.

The manifest covers a single page today. A site made of many files is the list
of block IDs the manifest already carries; the command line just doesn't expose
that yet.

### The frame protocol

Peers speak length-prefixed frames: a 32-bit length, a one-byte type, and the
payload, up to 8 MB. The types are:

| Type | Direction | Carries |
| --- | --- | --- |
| `HELLO` | both, first | node ID, membership certificate, links the node can speak |
| `HAVE` | either | a summary of the block IDs the sender holds |
| `WANT` | request | the block IDs the sender wants |
| `BLOCK` | response | one block's ID and its bytes |
| `RESOLVE` | request | a site name |
| `MANIFEST` | response | the signed manifest for that name |

A connection starts with both sides sending `HELLO` and reading the other's.
When a node has authorities configured, this is where the certificate is
checked, and the connection ends immediately if it fails. After that, either
side can request manifests and blocks while serving the other's requests on the
same connection.

### The .opennet file

The container layout, from the start of the file:

```
"ONET" | version | flags | dictionary length | zstd dictionary
repeated: block ID | raw length | compressed length | zstd compressed bytes
index:    count, then entries of block ID | offset | length, sorted by ID
footer:   offset of the index | "ONET"
```

The dictionary is trained on the text in the corpus before anything is written,
which is where the compression of similar pages comes from, and the trailing
index is what makes a lookup a binary search. A reader checks the magic at both
ends and recomputes each block's hash as it reads it, so a file that has been
truncated or had a byte flipped is rejected rather than served.

### Membership

Certificates are fixed-width and small: the node's public key, the issuing
authority's public key, the start and end of the validity window as unix
seconds, and the authority's signature over those fields. Verification takes
the set of authority keys the node trusts and the key the peer claims to be, so
the same code paths serve an open community network and a private one. The
difference between them is entirely in who holds the authority's private key.

A certificate proves identity and nothing more. It does not limit how many
certificates one person can ask for, and it says nothing about how fast a
member may send, so it does not by itself stop flooding. Rate limiting is a
separate layer and is not built yet. Radio jamming is not solvable in software
at all; no certificate stops someone transmitting noise on a channel.

## Repository layout

```
cmd/opennetd          the node: the five subcommands above
internal/cid          content IDs, a 32-byte BLAKE3 of the raw bytes
internal/frame        the length-prefixed frame codec and the six frame types
internal/store        the content-addressed block store
internal/container    the .opennet reader and writer
internal/member       identities, certificate authorities, and verification
internal/manifest     signing a site manifest and checking the signature
internal/session      the handshake, membership enforcement, and block transfer
internal/transport    the Transport interface; TCP is implemented, Wi-Fi Direct
                      and the custom radio are stubs behind it
internal/radio        the interface a custom radio module implements
```

Everything above the link talks to the `Transport` interface, which is why
adding the Wi-Fi and radio drivers later does not change the protocol. A
driver implements `Dial`, `Listen`, and a name, and the session layer cannot
tell the difference.

## Development

GitHub Actions runs on every push and every pull request. One job checks
formatting with `gofmt`, runs `go vet`, and runs the tests. Another
cross-compiles `opennetd` for every target in the table above, so a change that
builds on one operating system and breaks on another fails there rather than in
someone's hands.

Tagging a commit `v*` publishes a release. The workflow builds a binary for
each target and attaches them all to the release in one step, so the full set
appears on the releases page together.

## Status

Working and tested, end to end between two processes: the frame codec, content
addressing, the handshake with membership enforced, signed site manifests, and
block transfer that rejects a block whose bytes don't match its ID. The
`.opennet` reader and writer are tested too, including rejection of a truncated
or corrupted file.

Not built yet:

- Per-peer rate limiting, and a proof-of-work challenge for a peer that exceeds
  its budget. This is the layer that addresses flooding, which certificates
  cannot.
- Set reconciliation, so two nodes exchange a compact summary of what they hold
  and transfer only the difference instead of comparing lists.
- Serving a site from an `.opennet` file. `pack` writes the file and the reader
  can pull any block back out, but `serve` currently publishes one page from a
  plain file.
- Multi-file sites on the command line. The manifest already lists every block
  in a site; `serve` and `fetch` only handle the entry page so far.
- The Wi-Fi Direct driver and the custom-radio driver. Both have their
  interface defined and nothing behind it.

## License

[MIT](LICENSE)
