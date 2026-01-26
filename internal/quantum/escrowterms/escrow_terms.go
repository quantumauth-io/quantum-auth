package escrowterms

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	gethmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/google/uuid"
)

// Terms is what you sign and the client submits to the escrow contract.
type Terms struct {
	AppID        [32]byte       // bytes32 (UUID v4 left-padded)
	OrderID      [32]byte       // bytes32 (UUID v4 left-padded)
	Buyer        common.Address // msg.sender
	Amount       string         // uint256 (base-10 string, USDC base units)
	DelaySeconds uint64         // uint64
	ExpiresAt    uint64         // unix seconds
}

// UUIDStringToBytes32 converts a UUID v4 string into bytes32 by left-padding zeros
// and placing the UUID bytes in the last 16 bytes.
func UUIDStringToBytes32(s string) ([32]byte, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return [32]byte{}, fmt.Errorf("parse uuid: %w", err)
	}
	var out [32]byte
	copy(out[16:], u[:])
	return out, nil
}

func BuildTypedData(chainID uint64, verifyingContract common.Address, t Terms) apitypes.TypedData {
	chainIDBig := new(big.Int).SetUint64(chainID)
	chainIDHOD := (*gethmath.HexOrDecimal256)(chainIDBig) // ✅ correct type for your apitypes version

	return apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"EscrowTerms": {
				{Name: "appId", Type: "bytes32"},
				{Name: "orderId", Type: "bytes32"},
				{Name: "buyer", Type: "address"},
				{Name: "amount", Type: "uint256"},
				{Name: "delaySeconds", Type: "uint64"},
				{Name: "expiresAt", Type: "uint64"},
			},
		},
		PrimaryType: "EscrowTerms",
		Domain: apitypes.TypedDataDomain{
			Name:              "QAEscrow",
			Version:           "1",
			ChainId:           chainIDHOD, // ✅ now matches *math.HexOrDecimal256
			VerifyingContract: verifyingContract.Hex(),
		},
		Message: apitypes.TypedDataMessage{
			"appId":        common.BytesToHash(t.AppID[:]).Hex(),
			"orderId":      common.BytesToHash(t.OrderID[:]).Hex(),
			"buyer":        t.Buyer.Hex(),
			"amount":       t.Amount,
			"delaySeconds": fmt.Sprintf("%d", t.DelaySeconds),
			"expiresAt":    fmt.Sprintf("%d", t.ExpiresAt),
		},
	}
}

// SignTerms returns a 65-byte signature (r,s,v) as a 0x-prefixed hex string.
func SignTerms(priv *ecdsa.PrivateKey, typed apitypes.TypedData) (string, error) {
	msgHash, err := typed.HashStruct(typed.PrimaryType, typed.Message)
	if err != nil {
		return "", err
	}
	domainHash, err := typed.HashStruct("EIP712Domain", typed.Domain.Map())
	if err != nil {
		return "", err
	}

	digest := crypto.Keccak256(
		[]byte{0x19, 0x01},
		domainHash,
		msgHash,
	)

	sig, err := crypto.Sign(digest, priv)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(sig), nil
}

// ExpiresIn returns a unix seconds expiration timestamp.
func ExpiresIn(now time.Time, dur time.Duration) uint64 {
	return uint64(now.Add(dur).Unix())
}
