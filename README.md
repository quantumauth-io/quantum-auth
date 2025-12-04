# QuantumAuth
### Military-Grade Post-Quantum Authentication Framework
![Powered by QuantumAuth](https://img.shields.io/badge/Powered%20By-QuantumAuth-blue?style=for-the-badge&logo=shield)

QuantumAuth is the world's first **fully integrated TPM + Post-Quantum (PQ) signature authentication system**, designed to eliminate passwords, prevent replay attacks, and guarantee identity at the hardware level.

QuantumAuth provides:

- **TPM-backed hardware signatures**
- **ML-DSA-65 post-quantum signatures (CIRCL)**
- **Argon2id quantum-resistant password hashing**
- **Replay protection via Redis nonce-tracking**
- **Strict canonical request signing**
- **Zero bearer tokens**
- **Zero trust, zero reuse, zero impersonation**

This is authentication at a level previously considered “military-only”.

---

## 🚀 Architecture Overview

QuantumAuth consists of:

### **1. QuantumAuth Server (Go)**
Handles:
- User management
- Device registration (TPM + PQ public keys)
- Challenge generation & verification
- Secure middleware
- Replay protection
- Database (CockroachDB) + Redis

### **2. QuantumAuth Client (Cross-Platform Service)**
Runs locally on user devices:
- TPM key management
- PQ keypair generation
- Challenge signing
- CLI + local web dashboard
- Provides signed headers to any app

### **3. Zero-Trust Integration**
Any third-party server can authenticate requests by forwarding:

```Authorization: QuantumAuth user="...", device="...", ts="...", nonce="...", sig_tpm="...", sig_pq="..."```

Zero passwords.  
Zero secrets stored on servers.  
Zero attack surface.

---

## 📦 Installation (coming soon)

A full client installer will be provided for:

- Linux
- macOS (Intel + M1/M2)
- Windows
- Android
- iOS (via app extension)

---

## 📜 License

This project is licensed under the **Apache License 2.0** (see `LICENSE`).

Commercial licenses are available for SaaS companies, cybersecurity firms, and enterprises.  
See `COMMERCIAL-LICENSE.md` or contact:

**Ian Decentralize**  
📧 *insert your email here*

---

## 🏛 Attribution Requirement

If you use QuantumAuth in a product, website, or service, include:

Powered by QuantumAuth — created by Ian Dorion (Madeindreams)
https://github.com/Madeindreams/quantum-auth

This is **required** by the NOTICE file and Apache 2.0.

---

## 🤝 Contributing

See `CONTRIBUTING.md`.

---

## 🔐 Security

See `SECURITY.md` for vulnerability reporting.