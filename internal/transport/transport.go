// Package transport moves bytes between two nodes. Everything above it
// speaks only this interface, so the session layer is proven over TCP and
// later runs unchanged over Wi-Fi Direct or a custom radio module.
package transport

import (
	"io"
	"net"
)

// Conn is one live link to a peer. It is an io.ReadWriteCloser plus the
// peer's address, which is transport-specific text.
type Conn interface {
	io.ReadWriteCloser
	Remote() string
}

// Transport dials and accepts connections of one kind.
type Transport interface {
	// Dial opens a link to addr.
	Dial(addr string) (Conn, error)
	// Listen starts accepting links on addr and returns the address
	// actually bound, which may differ when addr asks for a random port.
	Listen(addr string) (Listener, error)
	// Name identifies the link kind in the Hello advertisement, so a peer
	// that lacks the hardware can fall back to one it has.
	Name() string
}

type Listener interface {
	Accept() (Conn, error)
	Close() error
	Addr() string
}

type tcpConn struct{ net.Conn }

func (c tcpConn) Remote() string { return c.Conn.RemoteAddr().String() }

type tcpListener struct{ net.Listener }

func (l tcpListener) Accept() (Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return tcpConn{c}, nil
}

func (l tcpListener) Addr() string { return l.Listener.Addr().String() }

// TCP speaks the protocol over plain TCP. It is the compatibility link for
// testing and for nodes that already share a network; it carries the same
// frames the radio links will.
type TCP struct{}

func (TCP) Name() string { return "tcp" }

func (TCP) Dial(addr string) (Conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return tcpConn{c}, nil
}

func (TCP) Listen(addr string) (Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return tcpListener{l}, nil
}
