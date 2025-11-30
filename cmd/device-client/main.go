package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

const (
	baseURL  = "http://localhost:1042"
	email    = "device@example.com"
	password = "secret"
)

// ===== PQ scheme =====

var pqScheme sign.Scheme

func init() {
	pqScheme = schemes.ByName("ML-DSA-65")
	if pqScheme == nil {
		log.Fatal("PQ scheme ML-DSA-65 not found in CIRCL")
	}
}

// ===== signed message (must match server) =====

type SignedMessage struct {
	ChallengeID string `json:"challenge_id"`
	DeviceID    string `json:"device_id"`
	Nonce       string `json:"nonce"`
	Purpose     string `json:"purpose"`
}

func buildSignedMessage(challengeID, deviceID, nonce string) ([]byte, error) {
	msg := SignedMessage{
		ChallengeID: challengeID,
		DeviceID:    deviceID,
		Nonce:       nonce,
		Purpose:     "auth",
	}
	return json.Marshal(msg)
}

// ===== HTTP DTOs =====

type registerUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type registerUserResponse struct {
	UserID string `json:"user_id"`
}

type registerDeviceRequest struct {
	UserEmail    string `json:"user_email"`
	TPMPublicKey string `json:"tpm_public_key"`
	PQPublicKey  string `json:"pq_public_key"`
}

type registerDeviceResponse struct {
	DeviceID string `json:"device_id"`
}

type authChallengeRequest struct {
	DeviceID string `json:"device_id"`
}

type authChallengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
	ExpiresAt   string `json:"expires_at"`
}

type authVerifyRequest struct {
	ChallengeID  string `json:"challenge_id"`
	DeviceID     string `json:"device_id"`
	Password     string `json:"password"`
	TPMSignature string `json:"tpm_signature"`
	PQSignature  string `json:"pq_signature"`
}

type authVerifyResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"user_id"`
}

// ===== main flow =====

func main() {
	log.Println("device-client starting")

	// 1) TPM client + public key
	tpmClient, tpmPubB64, err := NewTPMClient()
	if err != nil {
		log.Fatal("Init TPM failed:", err)
	}
	defer tpmClient.Close()
	log.Println("TPM public key (b64, trunc):", truncate(tpmPubB64))

	// 2) PQ keypair
	pk, sk, err := pqScheme.GenerateKey()
	if err != nil {
		log.Fatal("PQ keygen failed:", err)
	}
	pqPubBytes, err := pk.MarshalBinary()
	if err != nil {
		log.Fatal("PQ pub marshal failed:", err)
	}
	pqPubB64 := base64.RawStdEncoding.EncodeToString(pqPubBytes)
	log.Println("PQ public key (b64, trunc):", truncate(pqPubB64))

	// 3) Register user (ok if already exists)
	if err := registerUser(email, password); err != nil {
		log.Println("registerUser warning:", err)
	} else {
		log.Println("user registered")
	}

	// 4) Register device with TPM + PQ pubkeys
	deviceID, err := registerDevice(email, tpmPubB64, pqPubB64)
	if err != nil {
		log.Fatal("registerDevice failed:", err)
	}
	log.Println("device registered with id:", deviceID)

	// 5) Request challenge
	challengeID, nonce, err := requestChallenge(deviceID)
	if err != nil {
		log.Fatal("requestChallenge failed:", err)
	}
	log.Println("challenge:", challengeID, "nonce:", nonce)

	// 6) Build structured message
	msgBytes, err := buildSignedMessage(challengeID, deviceID, nonce)
	if err != nil {
		log.Fatal("buildSignedMessage failed:", err)
	}

	// 7) PQ sign
	pqSigBytes := pqScheme.Sign(sk, msgBytes, nil)
	if pqSigBytes == nil {
		log.Fatal("PQ sign failed:", err)
	}
	pqSigB64 := base64.RawStdEncoding.EncodeToString(pqSigBytes)

	// 8) TPM sign
	tpmSigB64, err := tpmClient.Sign(msgBytes)
	if err != nil {
		log.Fatal("TPM sign failed:", err)
	}

	// 9) Verify auth
	authenticated, userID, err := verifyAuth(challengeID, deviceID, password, tpmSigB64, pqSigB64)
	if err != nil {
		log.Fatal("verifyAuth error:", err)
	}

	log.Println("authenticated:", authenticated, "userID:", userID)
}

// ===== helpers: HTTP calls =====

func registerUser(email, password string) error {
	reqBody := registerUserRequest{Email: email, Password: password}
	b, _ := json.Marshal(reqBody)

	resp, err := http.Post(baseURL+"/users/register", "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		var out registerUserResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		log.Println("registerUser: created user", out.UserID)
		return nil
	}

	// conflict == already exists
	if resp.StatusCode == http.StatusConflict {
		io.Copy(io.Discard, resp.Body)
		log.Println("registerUser: user already exists")
		return nil
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("registerUser: status %d: %s", resp.StatusCode, string(bodyBytes))
}

func registerDevice(email, tpmPub, pqPub string) (string, error) {
	reqBody := registerDeviceRequest{
		UserEmail:    email,
		TPMPublicKey: tpmPub,
		PQPublicKey:  pqPub,
	}
	b, _ := json.Marshal(reqBody)

	resp, err := http.Post(baseURL+"/devices/register", "application/json", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("registerDevice: status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var out registerDeviceResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.DeviceID, nil
}

func requestChallenge(deviceID string) (string, string, error) {
	reqBody := authChallengeRequest{DeviceID: deviceID}
	b, _ := json.Marshal(reqBody)

	resp, err := http.Post(baseURL+"/auth/challenge", "application/json", bytes.NewReader(b))
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("requestChallenge: status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var out authChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	return out.ChallengeID, out.Nonce, nil
}

func verifyAuth(chID, devID, password, tpmSig, pqSig string) (bool, string, error) {
	reqBody := authVerifyRequest{
		ChallengeID:  chID,
		DeviceID:     devID,
		Password:     password,
		TPMSignature: tpmSig,
		PQSignature:  pqSig,
	}
	b, _ := json.Marshal(reqBody)

	resp, err := http.Post(baseURL+"/auth/verify", "application/json", bytes.NewReader(b))
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		var out authVerifyResponse
		if err := json.Unmarshal(bodyBytes, &out); err != nil {
			return false, "", err
		}
		return out.Authenticated, out.UserID, nil
	}

	if resp.StatusCode == http.StatusUnauthorized {
		var out authVerifyResponse
		_ = json.Unmarshal(bodyBytes, &out)
		return out.Authenticated, out.UserID, nil
	}

	return false, "", fmt.Errorf("verifyAuth: status %d: %s", resp.StatusCode, string(bodyBytes))
}

// tiny helper just for logs
func truncate(s string) string {
	if len(s) <= 32 {
		return s
	}
	return s[:32] + "..."
}
