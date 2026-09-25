// Package cid identifies content by the BLAKE3 hash of its raw bytes.
// A CID names bytes, not a location, so any node holding the same bytes
// can serve them and a receiver can check them without trusting the sender.
package cid

import (
	"bytes"
	"encoding/hex"

	"lukechampine.com/blake3"
)

const Size = 32

type ID [Size]byte

func Sum(b []byte) ID {
	return blake3.Sum256(b)
}

func (id ID) String() string { return hex.EncodeToString(id[:]) }

func (id ID) IsZero() bool { return id == ID{} }

// Parse decodes a 64-character hex CID.
func Parse(s string) (ID, error) {
	var id ID
	raw, err := hex.DecodeString(s)
	if err != nil {
		return id, err
	}
	if len(raw) != Size {
		return id, errLength
	}
	copy(id[:], raw)
	return id, nil
}

func Equal(a, b ID) bool { return bytes.Equal(a[:], b[:]) }

type lengthError struct{}

func (lengthError) Error() string { return "cid: wrong length" }

var errLength = lengthError{}
