package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/big"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// TPMClient holds the TPM connection and our signing key handle.
type TPMClient struct {
	rwc        io.ReadWriteCloser
	signHandle tpmutil.Handle
}

// NewTPMClient opens the TPM, creates a primary + signing key, and returns:
//   - client (for signing & cleanup)
//   - base64-encoded uncompressed ECC public key (0x04 || X || Y, 32 bytes each)
func NewTPMClient() (*TPMClient, string, error) {
	rwc, err := openTPM()
	if err != nil {
		return nil, "", err
	}

	primaryHandle, err := createPrimaryECC(rwc)
	if err != nil {
		_ = rwc.Close()
		return nil, "", err
	}

	signHandle, pubKeyUncompressed, err := createSigningKey(rwc, primaryHandle)
	if err != nil {
		_ = tpm2.FlushContext(rwc, primaryHandle)
		_ = rwc.Close()
		return nil, "", err
	}

	// We don't need the primary any more.
	_ = tpm2.FlushContext(rwc, primaryHandle)

	pubB64 := base64.RawStdEncoding.EncodeToString(pubKeyUncompressed)

	client := &TPMClient{
		rwc:        rwc,
		signHandle: signHandle,
	}

	return client, pubB64, nil
}

// openTPM tries /dev/tpmrm0 then /dev/tpm0.
func openTPM() (io.ReadWriteCloser, error) {
	paths := []string{"/dev/tpmrm0", "/dev/tpm0"}
	var lastErr error

	for _, p := range paths {
		rwc, err := tpm2.OpenTPM(p)
		if err == nil {
			return rwc, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no TPM device paths tried")
	}
	return nil, fmt.Errorf("no TPM device found: %w", lastErr)
}

// createPrimaryECC creates an ECC primary key under the owner hierarchy.
func createPrimaryECC(rwc io.ReadWriter) (tpmutil.Handle, error) {
	primaryTemplate := tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagStorageDefault |
			tpm2.FlagRestricted |
			tpm2.FlagDecrypt |
			tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
		},
	}

	hierarchies := []tpmutil.Handle{
		tpm2.HandleOwner,
		tpm2.HandleEndorsement,
		tpm2.HandlePlatform,
		tpm2.HandleNull,
	}

	var lastErr error
	for _, h := range hierarchies {
		handle, _, err := tpm2.CreatePrimary(
			rwc,
			h,
			tpm2.PCRSelection{},
			"", // parentPassword
			"", // ownerPassword
			primaryTemplate,
		)
		if err == nil {
			log.Printf("CreatePrimary succeeded in hierarchy 0x%x", h)
			return handle, nil
		}
		log.Printf("CreatePrimary failed in hierarchy 0x%x: %v", h, err)
		lastErr = err
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no hierarchy attempted")
	}
	return 0, fmt.Errorf("CreatePrimary failed for all hierarchies: %w", lastErr)
}

// createSigningKey creates a child ECC signing key under primaryHandle.
//
// It returns:
//   - signHandle: loaded key handle
//   - uncompressed public key bytes: 0x04 || X || Y (each 32 bytes)
func createSigningKey(rwc io.ReadWriter, primaryHandle tpmutil.Handle) (tpmutil.Handle, []byte, error) {
	signingTemplate := tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign |
			tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
		},
	}

	privBlob, pubBlob, _, _, _, err := tpm2.CreateKey(
		rwc,
		primaryHandle,
		tpm2.PCRSelection{},
		"", // parentPassword
		"", // ownerPassword
		signingTemplate,
	)
	if err != nil {
		return 0, nil, fmt.Errorf("CreateKey: %w", err)
	}

	signHandle, _, err := tpm2.Load(
		rwc,
		primaryHandle,
		"", // parentAuth
		pubBlob,
		privBlob,
	)
	if err != nil {
		return 0, nil, fmt.Errorf("Load signing key: %w", err)
	}

	// Read public part of signing key to extract X/Y coordinates.
	pub, _, _, err := tpm2.ReadPublic(rwc, signHandle)
	if err != nil {
		return 0, nil, fmt.Errorf("ReadPublic: %w", err)
	}

	genericKey, err := pub.Key()
	if err != nil {
		return 0, nil, fmt.Errorf("pub.Key: %w", err)
	}

	pubKey, ok := genericKey.(*ecdsa.PublicKey)
	if !ok {
		return 0, nil, fmt.Errorf("unexpected TPM pub key type %T", genericKey)
	}

	// Encode pubkey as uncompressed EC point: 0x04 || X || Y (32 bytes each)
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()

	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)

	uncompressed := append([]byte{0x04}, append(xPadded, yPadded...)...)

	return signHandle, uncompressed, nil
}

// Sign hashes msg with SHA-256 and signs with the TPM key.
// Returns base64-encoded R||S (each 32 bytes).
func (c *TPMClient) Sign(msg []byte) (string, error) {
	if c == nil || c.rwc == nil {
		return "", fmt.Errorf("TPMClient not initialized")
	}

	d := sha256.Sum256(msg)

	sig, err := tpm2.Sign(
		c.rwc,
		c.signHandle,
		"",   // password
		d[:], // digest
		nil,  // validation ticket
		&tpm2.SigScheme{
			Alg:  tpm2.AlgECDSA,
			Hash: tpm2.AlgSHA256,
		},
	)
	if err != nil {
		return "", fmt.Errorf("tpm2.Sign: %w", err)
	}
	if sig.ECC == nil {
		return "", fmt.Errorf("TPM returned non-ECC signature")
	}

	rBytes := fill32(sig.ECC.R)
	sBytes := fill32(sig.ECC.S)
	raw := append(rBytes, sBytes...)

	return base64.RawStdEncoding.EncodeToString(raw), nil
}

// fill32 pads a big.Int to 32 bytes big-endian.
func fill32(n *big.Int) []byte {
	out := make([]byte, 32)
	if n == nil {
		return out
	}
	nb := n.Bytes()
	if len(nb) > 32 {
		nb = nb[len(nb)-32:]
	}
	copy(out[32-len(nb):], nb)
	return out
}

// Close flushes TPM handles and closes the device.
func (c *TPMClient) Close() {
	if c == nil {
		return
	}
	if c.signHandle != 0 {
		if err := tpm2.FlushContext(c.rwc, c.signHandle); err != nil {
			log.Printf("FlushContext(signHandle) failed: %v", err)
		}
	}
	if c.rwc != nil {
		if err := c.rwc.Close(); err != nil {
			log.Printf("closing TPM rwc failed: %v", err)
		}
	}
}
