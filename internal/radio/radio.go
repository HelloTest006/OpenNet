// Package radio is the narrow interface a custom radio module implements.
//
// It is deliberately smaller than transport.Transport: a module only has to
// tune to a frequency and push or pull raw datagrams. Framing, retransmission,
// and the session protocol sit above it, in the radio Transport adapter, so a
// new piece of hardware is one driver and nothing else.
//
// This is the only path that emits anything other than standard 802.11
// frames, and it needs hardware a phone does not have. Commodity SDR tops out
// in the low megabits and LoRa in the low kilobits, well under Wi-Fi Direct,
// so it suits a node planted as neighborhood infrastructure rather than a
// handset. Its value is range and a channel that is not shared with every
// nearby router.
package radio

import "time"

// Module is one physical radio.
type Module interface {
	// Tune selects the center frequency in hertz and the channel bandwidth
	// in hertz. What the hardware can't do, it returns as an error.
	Tune(freqHz, bandwidthHz uint64) error
	// Send transmits one datagram. Datagrams are bounded by the module's MTU.
	Send(p []byte) error
	// Recv waits up to d for one datagram.
	Recv(d time.Duration) ([]byte, error)
	// MTU is the largest datagram Send accepts.
	MTU() int
	Close() error
}
