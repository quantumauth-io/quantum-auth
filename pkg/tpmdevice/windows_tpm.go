//go:build windows

package tpmdevice

import (
	"io"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// tpmRWCloser adapts a transport.TPMCloser to io.ReadWriteCloser so it works
// with github.com/google/go-tpm/legacy/tpm2.
type tpmRWCloser struct {
	io.ReadWriter
	closer io.Closer
}

func (t *tpmRWCloser) Close() error {
	return t.closer.Close()
}

// openTPM on Windows: use TBS via windowstpm.
func openTPM() (io.ReadWriteCloser, error) {
	tpm, err := windowstpm.Open()
	if err != nil {
		return nil, err
	}
	rw := transport.ToReadWriter(tpm)
	return &tpmRWCloser{
		ReadWriter: rw,
		closer:     tpm,
	}, nil
}
