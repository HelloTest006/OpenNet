# OpenNet

A peer-to-peer web where the nodes are ordinary devices. Each node holds a
slice of a corpus of sites and serves it directly to nearby peers. There is no
central server, no ISP, and no access point in the design; this repository is
the protocol that makes that work, proven first over plain TCP.

## What it is not

Three limits are baked into the design, and the code does not pretend otherwise.

- **A stock Wi-Fi chip speaks 802.11 frames and nothing else.** Arbitrary
  waveforms need a dedicated radio module. OpenNet therefore has two links: a
  custom-radio link for nodes built with that hardware, and a standard Wi-Fi
  link using ordinary 802.11 frames that runs on any phone or laptop. Peers
  advertise which links they have and fall back to the one they share.
- **It is not faster than the internet.** Wi-Fi Direct between two devices
  moves roughly 10-50 Mbps, the channel is shared and half-duplex, and each
  relay hop costs throughput. The gain is that it is free and needs no
  infrastructure.
- **One 500 MB file cannot hold millions of full websites.** At 500 bytes per
  site that is a title and a sentence. The realistic yield is thousands to a
  few tens of thousands of small static sites per 500 MB, and the corpus grows
  by adding nodes, not by compressing harder. Images barely compress at all.

## Layout

```
internal/cid        content IDs: BLAKE3 of the raw bytes
internal/frame      length-prefixed frame codec
internal/store      content-addressed block store
internal/container   the .opennet corpus file
internal/member      identities, certificate authorities, verification
internal/manifest    signing and checking a site descriptor
internal/transport  Transport interface; TCP works, Wi-Fi Direct and radio are stubs
internal/radio      interface a custom radio module implements
cmd/opennetd        the node
```

Content is addressed by the BLAKE3 hash of its bytes, so a node can relay a
block without being trusted to deliver it intact: the receiver recomputes the
hash and drops the block on any mismatch.

## Membership

A node proves it belongs to a network with a certificate signed by that
network's authority. The check is the same everywhere: the certificate must be
signed by an authority the node trusts, must be inside its validity window, and
must name the key the peer claims as its identity. A private network is one
whose authority key was never shared, so no outsider can be issued a
certificate that passes.

Certificates last days, not forever. Expiry is the revocation mechanism — a
leaked certificate stops working on its own, and there is no revocation list
for every node to learn.

```
opennetd authority -out community.authority
opennetd identity  -authority community.authority -out node.identity
opennetd serve     -listen 127.0.0.1:9731 -identity node.identity -trust community.authority
opennetd fetch     -peer 127.0.0.1:9731 -identity node.identity -trust community.authority -name news
```

Without `-trust` a node accepts anyone, which is only for trying the protocol
out. A certificate proves identity, not scarcity: it does not limit how fast a
member can send, so rate limiting is still a separate, unbuilt layer.

Every site is signed too. `fetch` checks the publisher's signature before it
writes anything, so a peer can relay a site but cannot alter one.

## The .opennet file

`opennetd pack` writes a corpus slice into one file. Blocks are stored by their
content ID, so an asset shared by many sites is stored once, and text blocks
are compressed with a dictionary trained on the corpus. On a test corpus of
2,000 small template-similar sites the file came out at about 160 bytes per
site, roughly 4x smaller than the raw pages — and that number is for pages that
share nearly everything. Images barely compress, and a site with real content
costs far more. The file is random access: one block is one binary search and
one read, not an unpack.

```
opennetd pack -out slice.opennet index.html style.css
```

## Building

Pure Go, no cgo, so cross-compiling is setting two variables:

```
GOOS=linux   GOARCH=arm64 go build -o opennetd ./cmd/opennetd
GOOS=android GOARCH=arm64 go build -o opennetd ./cmd/opennetd
```

GitHub Actions runs the tests and builds linux, windows, darwin, freebsd, and
android targets on every push. Tagging a release `v*` publishes a binary for
each of them to the releases page:

| File | Runs on |
| --- | --- |
| `opennetd-linux-amd64` | PCs and servers |
| `opennetd-linux-arm64` | Raspberry Pi 3/4/5, ARM servers |
| `opennetd-linux-arm-v7` | Older 32-bit ARM boards |
| `opennetd-windows-amd64.exe` | Windows PCs |
| `opennetd-windows-arm64.exe` | Windows on ARM |
| `opennetd-darwin-amd64` | Intel Macs |
| `opennetd-darwin-arm64` | Apple silicon Macs |
| `opennetd-freebsd-amd64` | FreeBSD |
| `opennetd-android-arm64` | Phones from the last decade, via Termux |
| `opennetd-android-arm-v7` | Older 32-bit phones, via Termux |

There is no `.apk`. A phone app needs an Android SDK, a manifest, and a
signing key this repository does not have, and the protocol has no Wi-Fi
Direct driver yet, so the app would do nothing the binary doesn't. The Android
binaries run as-is under [Termux](https://termux.dev). When the radio drivers
exist, an `.apk` belongs in the release alongside them.

## Status

The protocol is tested between two processes on one machine: frame codec,
content addressing, the handshake with membership enforced, signed sites, and
block transfer that rejects a block whose bytes don't match its ID.

Not built yet: per-peer rate limiting, set reconciliation, and the actual Wi-Fi
Direct and custom-radio drivers. Each slots in behind an interface that already
exists, so none of them changes the protocol.
