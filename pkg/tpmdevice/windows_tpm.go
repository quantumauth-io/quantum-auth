//go:build windows

package tpmdevice

import (
	"fmt"
	"io"
)

// openTPM for Windows.
// For now this just returns an error so the package compiles.
// Later you can wire this to real Windows TPM support.
func openTPM() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("tpmdevice: TPM support is not implemented on Windows yet")
}
