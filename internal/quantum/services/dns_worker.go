package services

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"github.com/quantumauth-io/quantum-auth/internal/quantum/constants"
	"github.com/quantumauth-io/quantum-auth/internal/quantum/database"
	"github.com/quantumauth-io/quantum-go-utils/log"
	"github.com/quantumauth-io/quantum-go-utils/qa/requests"
)

type AppVerifierConfig struct {
	IntervalSeconds   time.Duration // e.g. 30s, 1m, 5m
	BatchSize         int           // e.g. 200-1000
	DNSTimeoutSeconds time.Duration // e.g. 2s-5s
	DNSServerAddr     string        // optional explicit resolver (e.g. 1.1.1.1:53)
}

type AppVerifierRuntimeConfig struct {
	Interval      time.Duration
	BatchSize     int
	DNSTimeout    time.Duration
	DNSServerAddr string
}

type AppVerifierService struct {
	repo *database.QuantumAuthRepository
	cfg  AppVerifierRuntimeConfig
}

type AppRepo interface {
	GetAppsForVerificationScan(ctx context.Context, limit int) ([]*database.App, error)
	SetAppVerification(ctx context.Context, in database.SetAppVerificationInput) error
}

func NewAppVerifierService(repo *database.QuantumAuthRepository, cfg AppVerifierConfig) *AppVerifierService {
	interval := cfg.IntervalSeconds
	if interval <= 0 {
		interval = 60
	}

	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 500
	}

	dnsTimeout := cfg.DNSTimeoutSeconds
	if dnsTimeout <= 0 {
		dnsTimeout = 3
	}

	// Prefer explicit cfg value; fallback to env for compatibility
	dnsServerAddr := strings.TrimSpace(cfg.DNSServerAddr)
	if dnsServerAddr == "" {
		dnsServerAddr = strings.TrimSpace(os.Getenv("DNS_SERVER_ADDR"))
	}
	dnsServerAddr = normalizeDNSServerAddr(dnsServerAddr)

	return &AppVerifierService{
		repo: repo,
		cfg: AppVerifierRuntimeConfig{
			Interval:      interval * time.Second,
			BatchSize:     batchSize,
			DNSTimeout:    dnsTimeout * time.Second,
			DNSServerAddr: dnsServerAddr,
		},
	}
}

func normalizeDNSServerAddr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// If it looks like an IPv6 literal without brackets and without port, assume :53.
	// (If you need IPv6+port, provide it as "[::1]:53".)
	if strings.Count(s, ":") >= 2 && !strings.HasPrefix(s, "[") && !strings.Contains(s, "]:") {
		// no port; keep as-is (Dial will likely fail). Encourage bracket form.
		// Prefer being explicit rather than guessing wrong.
		return s
	}

	// If no port provided (IPv4 or hostname), append :53
	if !strings.Contains(s, ":") {
		return s + ":53"
	}

	return s
}

func (s *AppVerifierService) Start(ctx context.Context) {
	log.Info("App verifier started",
		"interval", s.cfg.Interval.String(),
		"batch_size", s.cfg.BatchSize,
		"dns_timeout", s.cfg.DNSTimeout.String(),
		"dns_server_addr", s.cfg.DNSServerAddr,
	)

	t := time.NewTicker(s.cfg.Interval)

	go func() {
		defer t.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Info("App verifier stopped")
				return
			case <-t.C:
				s.runOnce(ctx)
			}
		}
	}()
}

func (s *AppVerifierService) runOnce(ctx context.Context) {
	apps, err := s.repo.GetAppsForVerificationScan(ctx, s.cfg.BatchSize)
	if err != nil || len(apps) == 0 {
		return
	}

	for _, a := range apps {
		// Domain TXT
		domainVerified, domainErr := s.lookupTXT(ctx, a.Domain, a.VerificationToken)
		if domainErr != nil {
			log.Warn("App verifier: domain DNS lookup failed",
				"app_id", a.AppID,
				"domain", a.Domain,
				"error", domainErr,
			)
			// Unknown -> don't change state
			continue
		}

		// Backend host TXT (strip scheme/path/port, then treat as "domain" input to lookupTXT)
		hostName := requests.HostnameForDNS(a.BackendHost)
		if hostName == "" {
			log.Warn("App verifier: backend host invalid/empty",
				"app_id", a.AppID,
				"backend_host", a.BackendHost,
			)
			// Unknown -> don't change state
			continue
		}

		hostVerified, hostErr := s.lookupTXT(ctx, hostName, a.VerificationToken)
		if hostErr != nil {
			log.Warn("App verifier: backend host DNS lookup failed",
				"app_id", a.AppID,
				"backend_host", a.BackendHost,
				"host_name", hostName,
				"error", hostErr,
			)
			// Unknown -> don't change state
			continue
		}

		// Both lookups succeeded => authoritative result.
		verified := domainVerified && hostVerified

		now := time.Now()
		var lastVerified *time.Time
		if verified {
			lastVerified = &now
		} else {
			lastVerified = nil
		}

		if err := s.repo.SetAppVerification(ctx, database.SetAppVerificationInput{
			AppID:          a.AppID,
			Verified:       verified,
			LastCheckedAt:  now,
			LastVerifiedAt: lastVerified,
		}); err != nil {
			log.Warn("App verifier: failed to persist verification",
				"app_id", a.AppID,
				"error", err,
			)
			continue
		}
	}
}

func (s *AppVerifierService) lookupTXT(ctx context.Context, domain, token string) (bool, error) {
	fqdn, err := buildQATXTName(domain)
	if err != nil {
		return false, err
	}

	want := constants.QADNSRecordValuePrefix + token

	var lastErr error
	for _, r := range s.resolverChain() {
		lookupCtx, cancel := context.WithTimeout(ctx, s.cfg.DNSTimeout)
		txts, e := r.LookupTXT(lookupCtx, fqdn)
		cancel()

		if e != nil {
			lastErr = e
			continue
		}

		// Resolver successfully answered. Now check for the exact token.
		for _, v := range txts {
			if strings.TrimSpace(v) == want {
				return true, nil
			}
		}
		return false, nil
	}

	return false, lastErr
}

func buildQATXTName(domain string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return "", &net.DNSError{Err: "empty domain", Name: domain}
	}

	// If someone accidentally passed a URL, strip scheme/path/port.
	if strings.Contains(d, "://") {
		host := requests.HostnameForDNS(d)
		if host == "" {
			return "", &net.DNSError{Err: "invalid domain", Name: domain}
		}
		d = host
	}

	// Remove trailing dot if present.
	d = strings.TrimSuffix(d, ".")

	// Ensure we always generate: <QADNSRecordName><domain>
	// where QADNSRecordName may or may not already include a trailing dot.
	prefix := strings.TrimSpace(constants.QADNSRecordName)
	prefix = strings.TrimSuffix(prefix, ".")

	// Avoid double prefixing if caller already provided it.
	if d == prefix || strings.HasPrefix(d, prefix+".") {
		return d + ".", nil
	}

	return prefix + "." + d + ".", nil
}

func (s *AppVerifierService) resolverChain() []*net.Resolver {
	var out []*net.Resolver

	// 1) Explicit resolver from config/env (lets you force public DNS in VPC)
	if s.cfg.DNSServerAddr != "" {
		out = append(out, resolverForServer(s.cfg.DNSServerAddr, s.cfg.DNSTimeout))
	}

	// 2) System resolver (AWS VPC resolver is usually here)
	out = append(out, net.DefaultResolver)

	// 3) Public fallbacks (helpful for split-horizon/private zones)
	out = append(out,
		resolverForServer("1.1.1.1:53", s.cfg.DNSTimeout),
		resolverForServer("8.8.8.8:53", s.cfg.DNSTimeout),
	)

	return out
}

func resolverForServer(serverAddr string, timeout time.Duration) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Normalize network: udp4/tcp4/udp6/tcp6 → udp/tcp
			switch network {
			case "udp", "tcp":
				// ok
			case "udp4", "udp6":
				network = "udp"
			case "tcp4", "tcp6":
				network = "tcp"
			default:
				network = "udp"
			}

			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, serverAddr)
		},
	}
}
