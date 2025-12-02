# QuantumAuth
### **Military-Grade, Post-Quantum, Hardware-Backed Authentication**

QuantumAuth is a next-generation authentication framework delivering **the strongest security posture currently achievable in civilian technology**.  
It combines **TPM hardware-rooted signing**, **post-quantum cryptography**, and **Argon2id quantum-resistant password hashing** — all **without issuing bearer tokens**.

Even if attackers steal your entire database or intercept all network traffic, **authentication cannot be forged**.

This architecture mirrors — and in some areas exceeds — principles used in **classified military and critical-infrastructure systems** (to the extent publicly known).

---

## 🚀 Key Security Features

### ✅ **1. Hardware-Rooted TPM Signatures (ECC P-256, non-extractable)**
Each client device generates and stores its signing key **inside the TPM**.  
The private key **never leaves hardware** and cannot be extracted or brute-forced.

Every authentication step requires a real TPM signature — making stolen credentials useless.

---

### ✅ **2. Post-Quantum Signatures (ML-DSA-65)**
QuantumAuth double-signs every request using a **post-quantum signature scheme** from Cloudflare’s CIRCL.

This protects against:

- Future quantum computers
- Traffic recording + delayed decryption
- Long-term cryptanalytic attacks

Even if classical crypto falls, your auth remains intact.

---

### ✅ **3. Argon2id Quantum-Resistant Password Hashing**
Passwords are hashed using **Argon2id**, the cutting-edge password hashing algorithm designed to resist:

- GPU/ASIC brute force
- Memory-hard attacks
- Quantum amplitude amplification

A stolen database doesn’t compromise user passwords.

---

### ✅ **4. Zero Bearer Tokens — Every Request Must Be Signed**
QuantumAuth **does not generate tokens** (JWT, OAuth tokens, sessions, etc.).

Why?  
Bearer tokens behave like **keys that unlock everything** if stolen.

Instead, every request must be signed in real time:

TPM hardware signature + Post-Quantum signature + Argon2 password

Token theft becomes **meaningless**.

---

### ✅ **5. Redis-Backed Replay Protection**
Each request includes:

- A timestamp
- A unique per-device nonce
- UserID
- DeviceID

Nonces are tracked in Redis and rejected once used.

Replay attacks become **impossible**, even on insecure networks.

---

## 🛡️ Why This Is (Probably) The Most Secure Public Auth System on Earth

QuantumAuth requires **two independent cryptographic signatures**, both valid at the same time:

TPM (hardware sealed key)
+
Post-Quantum signature
+
Argon2id password check


This stack is unmatched in public authentication systems.

| Security Property                | Supported | How |
|--------------------------------|-----------|-----|
| Password database stolen        | ✅ | Argon2id hashing |
| Token/session hijacking         | ✅ | No tokens used |
| MITM attacks                    | ✅ | TPM + PQ verification |
| Replay attacks                  | ✅ | Redis nonce tracking |
| Quantum attacks                 | ✅ | ML-DSA post-quantum signing |
| Device cloning                  | ❌ | TPM keys cannot be extracted |
| Credential phishing             | ⚠️ | Signing each request limits attacker value |

Short of classified or government-restricted systems, **there is nothing else with this combination of guarantees**.

---

## 🚧 Development Status

QuantumAuth is designed as:

- A **Golang backend authentication layer**
- A **hardware-backed device client**
- Future: **JS/TS library**, **Secure-Enclave mobile support**, **PQ-Passkey integration**

Follow the project to get early access to:

- Documentation
- Client SDKs
- Examples
- Production deployment guidance

---

## ⭐ Stay Updated

This project is under active development.  
Star the repo to follow progress and upcoming announcements.


## dev
generate swagger
```bash
 swag init -g cmd/quantum-auth/main.go -o docs
```

