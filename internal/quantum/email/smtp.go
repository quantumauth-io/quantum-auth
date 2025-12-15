package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type SMTPConfig struct {
	Host     string // e.g. "smtp.protonmail.ch"
	Port     int    // 587 (STARTTLS) or 465 (TLS)
	Username string // Proton SMTP username
	Password string // SMTP token / API key
	Timeout  time.Duration
	UseTLS   bool // true for implicit TLS (465)
	StartTLS bool // true for STARTTLS (587)
}

type SMTPSender struct {
	cfg SMTPConfig
}

func NewSMTPSender(cfg SMTPConfig) *SMTPSender {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	cfg.Timeout *= time.Second
	return &SMTPSender{cfg: cfg}
}

func (s *SMTPSender) Send(ctx context.Context, msg Message) error {
	if msg.To == "" || msg.Subject == "" || (msg.TextBody == "" && msg.HTMLBody == "") {
		return fmt.Errorf("email: missing required fields (to/subject/body)")
	}
	if msg.FromAddr == "" {
		return fmt.Errorf("email: FromAddr required")
	}
	if s.cfg.Host == "" || s.cfg.Port == 0 {
		return fmt.Errorf("email: missing smtp host/port")
	}

	// 1) Resolve hostname once (fast timeout) to avoid intermittent systemd-resolved stub hiccups.
	resolver := &net.Resolver{}
	ctxDNS, cancelDNS := context.WithTimeout(ctx, 3*time.Second)
	addrs, err := resolver.LookupHost(ctxDNS, s.cfg.Host)
	cancelDNS()
	if err != nil {
		return fmt.Errorf("email: dns lookup %s: %w", s.cfg.Host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("email: dns lookup %s returned no addresses", s.cfg.Host)
	}

	// 2) Dial each resolved IP until one works (avoid DNS during Dial).
	dialer := net.Dialer{Timeout: s.cfg.Timeout}

	var conn net.Conn
	var lastErr error
	for _, ip := range addrs {
		target := net.JoinHostPort(ip, strconv.Itoa(s.cfg.Port))

		cctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
		tryConn, err := dialer.DialContext(cctx, "tcp", target)
		cancel()

		if err == nil {
			conn = tryConn
			lastErr = nil
			break
		}
		lastErr = err
	}
	if lastErr != nil {
		return fmt.Errorf("email: dial smtp (all addresses failed for %s:%d): %w", s.cfg.Host, s.cfg.Port, lastErr)
	}
	defer conn.Close()

	var c *smtp.Client

	// Implicit TLS (465)
	if s.cfg.UseTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: s.cfg.Host, // IMPORTANT: keep hostname for SNI/cert validation
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("email: tls handshake: %w", err)
		}
		c, err = smtp.NewClient(tlsConn, s.cfg.Host) // IMPORTANT: host is hostname, not IP
		if err != nil {
			return fmt.Errorf("email: new client: %w", err)
		}
	} else {
		c, err = smtp.NewClient(conn, s.cfg.Host) // IMPORTANT: host is hostname, not IP
		if err != nil {
			return fmt.Errorf("email: new client: %w", err)
		}
	}
	defer c.Close()

	// STARTTLS (587)
	if s.cfg.StartTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{
				ServerName: s.cfg.Host, // IMPORTANT: keep hostname for SNI/cert validation
				MinVersion: tls.VersionTLS12,
			}); err != nil {
				return fmt.Errorf("email: starttls: %w", err)
			}
		} else {
			return fmt.Errorf("email: server does not support STARTTLS")
		}
	}

	// Enforce TLS before AUTH if we have credentials.
	// Proton’s SMTP token/API key should never be sent without TLS.
	if s.cfg.Username != "" || s.cfg.Password != "" {
		_, ok := c.TLSConnectionState()
		if !ok {
			return fmt.Errorf("email: refusing to AUTH without TLS")
		}
	}

	// Auth
	if s.cfg.Username != "" {
		auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("email: auth: %w", err)
			}
		}
	}

	if err := c.Mail(msg.FromAddr); err != nil {
		return fmt.Errorf("email: MAIL FROM: %w", err)
	}
	if err := c.Rcpt(msg.To); err != nil {
		return fmt.Errorf("email: RCPT TO: %w", err)
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("email: DATA: %w", err)
	}

	raw := buildMIME(msg)
	if _, err := w.Write([]byte(raw)); err != nil {
		_ = w.Close()
		return fmt.Errorf("email: write: %w", err)
	}

	// IMPORTANT: close DATA to finalize the message with the server
	if err := w.Close(); err != nil {
		return fmt.Errorf("email: close data: %w", err)
	}

	// QUIT is best-effort. Some servers / net/smtp combos surface success text as an "error".
	_ = c.Quit()
	return nil
}

func buildMIME(m Message) string {
	from := m.FromAddr
	if m.FromName != "" {
		from = fmt.Sprintf("%s <%s>", m.FromName, m.FromAddr)
	}

	headers := map[string]string{
		"From":         from,
		"To":           m.To,
		"Subject":      encodeHeader(m.Subject),
		"MIME-Version": "1.0",
	}

	if m.TextBody != "" && m.HTMLBody != "" {
		boundary := "qa-boundary-9f2b1a2c"
		headers["Content-Type"] = fmt.Sprintf(`multipart/alternative; boundary="%s"`, boundary)

		var b strings.Builder
		writeHeaders(&b, headers)
		b.WriteString("\r\n")

		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(m.TextBody + "\r\n")

		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(m.HTMLBody + "\r\n")

		b.WriteString("--" + boundary + "--\r\n")
		return b.String()
	}

	if m.HTMLBody != "" {
		headers["Content-Type"] = "text/html; charset=UTF-8"
	} else {
		headers["Content-Type"] = "text/plain; charset=UTF-8"
	}
	headers["Content-Transfer-Encoding"] = "8bit"

	var b strings.Builder
	writeHeaders(&b, headers)
	b.WriteString("\r\n")

	if m.HTMLBody != "" {
		b.WriteString(m.HTMLBody)
	} else {
		b.WriteString(m.TextBody)
	}

	if !strings.HasSuffix(b.String(), "\r\n") {
		b.WriteString("\r\n")
	}
	return b.String()
}

func writeHeaders(b *strings.Builder, h map[string]string) {
	order := []string{"From", "To", "Subject", "MIME-Version", "Content-Type", "Content-Transfer-Encoding"}
	for _, k := range order {
		if v, ok := h[k]; ok && v != "" {
			b.WriteString(k + ": " + v + "\r\n")
		}
	}
}

func encodeHeader(s string) string { return s }
