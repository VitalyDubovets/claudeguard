// Package sysutil holds small helpers for talking to the operating system:
// running system tools, copying files, finding ports.
package sysutil

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"os"
	"strings"
)

// ErrUnsupported is what the system-specific parts return elsewhere.
var ErrUnsupported = errors.New("only macOS, Windows and Linux are supported; `serve` works everywhere")

// ShortErr trims an error down to its last, most specific part.
func ShortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}

// SameFile reports whether two files have the same contents.
func SameFile(a, b string) bool {
	sum := func(p string) []byte {
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return nil
		}
		return h.Sum(nil)
	}
	x, y := sum(a), sum(b)
	return x != nil && bytes.Equal(x, y)
}

// FreePort asks the system for a spare loopback TCP port.
func FreePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}
