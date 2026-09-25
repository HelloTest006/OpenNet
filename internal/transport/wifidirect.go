package transport

import "errors"

// ErrNoWiFiDirect reports that this build has no Wi-Fi Direct driver. The
// standard-Wi-Fi link uses ordinary 802.11 frames through the OS Wi-Fi
// Direct stack (Android WifiP2pManager, Windows Wi-Fi Direct, Linux
// wpa_supplicant p2p). That code is platform-specific and lands behind this
// same Transport interface; until then the type exists so nodes can
// advertise the link they intend to grow into.
type WiFiDirect struct{}

func (WiFiDirect) Name() string { return "wifi" }

func (WiFiDirect) Dial(string) (Conn, error) { return nil, errNoWiFi }

func (WiFiDirect) Listen(string) (Listener, error) { return nil, errNoWiFi }

var errNoWiFi = errors.New("transport: no Wi-Fi Direct driver in this build")
