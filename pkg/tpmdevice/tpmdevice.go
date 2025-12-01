package tpmdevice

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const defaultHandle = tpmutil.Handle(0x81000001)

// Client is a TPM-backed signing client.
type Client interface {
	PublicKey() []byte                  // uncompressed 0x04||X||Y
	PublicKeyB64() string               // base64url(0x04||X||Y)
	Sign(msg []byte) ([]byte, error)    // raw R||S (64 bytes)
	SignB64(msg []byte) (string, error) // base64url(R||S)
	Close() error
}

type client struct {
	rwc    io.ReadWriteCloser
	handle tpmutil.Handle
	pub    []byte
	pubB64 string
}

type Config struct {
	Handle   tpmutil.Handle
	ForceNew bool
	Logger   *log.Logger
}

func logf(logger *log.Logger, format string, args ...interface{}) {
	if logger != nil {
		logger.Printf(format, args...)
	}
}

func New(ctx context.Context, handle tpmutil.Handle) (Client, error) {
	return NewWithConfig(ctx, Config{Handle: handle})
}

func NewWithConfig(_ context.Context, cfg Config) (Client, error) {
	handle := cfg.Handle
	if handle == 0 {
		handle = defaultHandle
	}

	rwc, err := openTPM()
	if err != nil {
		return nil, err
	}

	if cfg.ForceNew {
		_ = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, handle, handle)
	}

	if !cfg.ForceNew {
		pub, _, _, err := tpm2.ReadPublic(rwc, handle)
		if err == nil {
			uncompressed, err := publicToUncompressed(pub)
			if err != nil {
				_ = rwc.Close()
				return nil, err
			}
			pubB64 := base64.RawStdEncoding.EncodeToString(uncompressed)
			logf(cfg.Logger, "tpmdevice: using existing key at 0x%x", handle)
			return &client{
				rwc:    rwc,
				handle: handle,
				pub:    uncompressed,
				pubB64: pubB64,
			}, nil
		}
		logf(cfg.Logger, "tpmdevice: no existing key at 0x%x: %v", handle, err)
	}

	// Create a new primary signing key under some hierarchy.
	transient, uncompressed, err := createPrimarySigningKey(rwc, cfg.Logger)
	if err != nil {
		_ = rwc.Close()
		return nil, err
	}

	// Persist at the chosen handle.
	// Try to persist at the chosen handle.
	// If EvictControl fails (hierarchy issues, permissions, etc.),
	// fall back to using the transient handle instead of aborting.
	if err := tpm2.EvictControl(rwc, "", tpm2.HandleOwner, transient, handle); err != nil {
		logf(cfg.Logger, "tpmdevice: EvictControl failed (%v), using transient handle 0x%x", err, transient)

		pubB64 := base64.RawStdEncoding.EncodeToString(uncompressed)
		return &client{
			rwc:    rwc,
			handle: transient, // keep transient handle
			pub:    uncompressed,
			pubB64: pubB64,
		}, nil
	}

	// EvictControl succeeded; we can flush transient and use the persistent handle.
	_ = tpm2.FlushContext(rwc, transient)

	pubB64 := base64.RawStdEncoding.EncodeToString(uncompressed)
	logf(cfg.Logger, "tpmdevice: created key at 0x%x", handle)

	return &client{
		rwc:    rwc,
		handle: handle, // persistent
		pub:    uncompressed,
		pubB64: pubB64,
	}, nil
}

// createPrimarySigningKey creates a transient ECC signing key and returns
// its handle + uncompressed public key.
func createPrimarySigningKey(rwc io.ReadWriter, logger *log.Logger) (tpmutil.Handle, []byte, error) {
	template := tpm2.Public{
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
			template,
		)
		if err != nil {
			logf(logger, "tpmdevice: CreatePrimary failed in 0x%x: %v", h, err)
			lastErr = err
			continue
		}

		logf(logger, "tpmdevice: CreatePrimary OK in 0x%x (0x%x)", h, handle)

		pub, _, _, err := tpm2.ReadPublic(rwc, handle)
		if err != nil {
			_ = tpm2.FlushContext(rwc, handle)
			return 0, nil, fmt.Errorf("ReadPublic: %w", err)
		}

		uncompressed, err := publicToUncompressed(pub)
		if err != nil {
			_ = tpm2.FlushContext(rwc, handle)
			return 0, nil, err
		}

		return handle, uncompressed, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no hierarchy attempted")
	}
	return 0, nil, fmt.Errorf("CreatePrimary failed: %w", lastErr)
}

func publicToUncompressed(pub tpm2.Public) ([]byte, error) {
	genericKey, err := pub.Key()
	if err != nil {
		return nil, fmt.Errorf("pub.Key: %w", err)
	}
	ec, ok := genericKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected key type %T", genericKey)
	}
	return uncompressedFromECDSA(ec), nil
}

// --- Client methods ---

func (c *client) PublicKey() []byte {
	return append([]byte(nil), c.pub...)
}

func (c *client) PublicKeyB64() string {
	return c.pubB64
}

func (c *client) Sign(msg []byte) ([]byte, error) {
	if c == nil || c.rwc == nil {
		return nil, fmt.Errorf("tpmdevice: client not initialized")
	}
	d := sha256.Sum256(msg)
	sig, err := tpm2.Sign(
		c.rwc,
		c.handle,
		"",
		d[:],
		nil,
		&tpm2.SigScheme{
			Alg:  tpm2.AlgECDSA,
			Hash: tpm2.AlgSHA256,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("tpmdevice: Sign: %w", err)
	}
	if sig.ECC == nil {
		return nil, fmt.Errorf("tpmdevice: TPM returned non-ECC signature")
	}
	raw := append(pad32(sig.ECC.R), pad32(sig.ECC.S)...)
	return raw, nil
}

func (c *client) SignB64(msg []byte) (string, error) {
	raw, err := c.Sign(msg)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(raw), nil
}

func (c *client) Close() error {
	if c == nil {
		return nil
	}
	if c.rwc != nil {
		if err := c.rwc.Close(); err != nil {
			return fmt.Errorf("tpmdevice: close: %w", err)
		}
	}
	return nil
}
