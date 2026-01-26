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
	DNSServerAddr     string
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

// If your repo already is *database.QuantumAuthRepository, it will satisfy this interface
// as long as it has the methods above.

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

	dnsServerAddr := strings.TrimSpace(os.Getenv("DNS_SERVER_ADDR"))

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

func (s *AppVerifierService) dnsResolver() *net.Resolver {
	if s.cfg.DNSServerAddr == "" {
		return net.DefaultResolver
	}

	return &net.Resolver{
		PreferGo: true, // critical: makes Dial take effect on all platforms
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: s.cfg.DNSTimeout}

			// Prefer UDP for DNS; use TCP automatically if caller asks for tcp.
			// But net.Resolver may pass "udp" or "tcp" here depending on retry behavior.
			if network != "udp" && network != "tcp" {
				network = "udp"
			}

			return d.DialContext(ctx, network, s.cfg.DNSServerAddr)
		},
	}
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
	host := constants.QADNSRecordName + strings.ToLower(strings.TrimSpace(domain))
	want := constants.QADNSRecordValuePrefix + token

	lookupCtx, cancel := context.WithTimeout(ctx, s.cfg.DNSTimeout)
	defer cancel()

	resolver := s.dnsResolver()
	txts, err := resolver.LookupTXT(lookupCtx, host)
	if err != nil {
		return false, err
	}

	for _, v := range txts {
		if strings.TrimSpace(v) == want {
			return true, nil
		}
	}
	return false, nil
}
