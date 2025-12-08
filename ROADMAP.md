# QuantumAuth Roadmap

## Phase 1 --- Core System Stabilization (Now → Q1)

### Backend / QA Server

-   [ ] Finalize Dockerized server build (multi-stage, optimized
    runtime)
-   [ ] Add healthcheck endpoint (`/healthz`)
-   [ ] Add internal metrics endpoint (`/metrics` for Prometheus\`)
-   [ ] Complete CockroachDB schema + migrations
-   [ ] Implement connection pooling + retry logic
-   [ ] Harden configuration system (env overrides + config.yaml)

### Client SDK

-   [ ] Unify TPM + Enclave abstraction into a single signing interface
-   [ ] Improve Windows/Linux/Mac platform detection
-   [ ] Add structured debug logging
-   [ ] Implement cross-platform binary release pipeline (GoReleaser)

### Security

-   [ ] Add signature validation benchmarking
-   [ ] Rate limiting per device / per user
-   [ ] Add audit logging for key usage + challenge flows

## Phase 2 --- Developer Experience & APIs (Q1 → Q2)

### Public APIs

-   [ ] Add OpenAPI/Swagger documentation
-   [ ] Provide typed SDK responses and error codes
-   [ ] Add admin API for device revocation + key rotation
-   [ ] Add JWT / session integration for legacy apps

### Docs

-   [ ] Complete "Why QuantumAuth" section
-   [ ] Add comparison pages (WebAuthn, KeyPass, Passkeys)
-   [ ] Architecture diagrams for signup, login, and device binding
-   [ ] Quickstart guide for developers

### Tooling

-   [ ] Local development docker-compose setup
-   [ ] Simulated TPM mode for CI pipelines
-   [ ] CLI tool for interacting with QA server (admin operations)

## Phase 3 --- Multi-Platform Device Support (Q2 → Q3)

### Desktop Platforms

-   [ ] macOS Secure Enclave support (P256 & Ed25519)
-   [ ] Windows Hello + TPM 2.0 integration
-   [ ] Linux TPM 2.0 with fallback to soft-HSM

### Mobile Platforms

-   [ ] Android StrongBox + Keystore integration
-   [ ] iOS Secure Enclave with proper attestation
-   [ ] Cross-platform mobile SDK (Kotlin/Swift bindings)

### Fallback modes

-   [ ] Recovery keys (encrypted locally)
-   [ ] Optional passcode-protected signing

## Phase 4 --- Quantum-Safe Engine (Q3 → Q4)

### PQ Signatures

-   [ ] Add Dilithium2/3/5 signing support
-   [ ] Hybrid signatures (ECDSA + PQ)
-   [ ] Performance optimization + benchmarking suite

### PQ Key Storage

-   [ ] Evaluate secure PQ key storage options on TEEs/TPM
-   [ ] Device-bound PQ attestation experiments
-   [ ] Add PQ migration path for existing devices

## Phase 5 --- Cloud & Infrastructure (Q3 → Q4)

### Deployment Targets

-   [ ] Fly.io / Railway / Cloudflare Workers-compatible distribution
-   [ ] Standalone "Enterprise Edition" with multi-node clustering
-   [ ] Autoscaling strategy (stateless API + CockroachDB scale)

### Monitoring

-   [ ] Grafana dashboards
-   [ ] Alert rules for authentication failures
-   [ ] Usage analytics (anonymous + privacy-preserving)

## Phase 6 --- Extended Ecosystem (Future)

### Crypto Wallet Integration

-   [ ] Transaction signing API for Bitcoin/Ethereum/Solana
-   [ ] Device-bound wallet identities
-   [ ] Secure signing confirmation flows

### 3rd-Party Integrations

-   [ ] OAuth2 / OIDC bridge for legacy apps
-   [ ] Passkeys compatibility layer
-   [ ] Browser extension for desktop apps

## Notes

QuantumAuth is designed as a device-bound, hardware-rooted
authentication platform that replaces passwords, avoids phishing, and is
secured against quantum attacks.
