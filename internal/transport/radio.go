package transport

import "errors"

// ErrNoRadio reports that this build has no custom-radio driver. The native
// link drives a dedicated module — a USB or SPI software-defined radio, or a
// sub-GHz board — through the Radio interface in internal/radio. A stock
// Wi-Fi chip cannot speak it. The driver lands behind this same Transport
// interface, and a peer without the module falls back to the "wifi" link
// advertised alongside it.
type Radio struct{}

func (Radio) Name() string { return "radio" }

func (Radio) Dial(string) (Conn, error) { return nil, errNoRadio }

func (Radio) Listen(string) (Listener, error) { return nil, errNoRadio }

var errNoRadio = errors.New("transport: no custom radio driver in this build")
