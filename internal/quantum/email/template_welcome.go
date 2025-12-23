package email

import (
	"fmt"
	"html"
	"strings"
	"time"
)

type emailTheme struct {
	Primary500 string // sky-500
	Primary600 string // sky-600-ish
	Accent500  string // blue-500
	Bg950      string // deep background
	Bg900      string
	Surface    string // rgba white overlay
	Border     string // rgba border
	Text       string // near-white
	Muted      string
	Subtle     string
}

func qaEmailTheme() emailTheme {
	return emailTheme{
		Primary600: "#0284C7",
		Primary500: "#0EA5E9",
		Accent500:  "#3B82F6",

		Bg950: "#030712",
		Bg900: "#081022",

		// Use solid colors for email (no rgba)
		Surface: "#0B1630", // slightly lighter navy surface
		Border:  "#1C2A4A", // subtle border

		Text:   "#F1F5F9", // slate-100
		Muted:  "#CBD5E1", // slate-300
		Subtle: "#94A3B8", // slate-400
	}
}

// WelcomeEmailHTML returns a dark, theme-aligned HTML email.
// Table-based for best compatibility across email clients.
func WelcomeEmailHTML(username, docsURL, logoURL string) string {
	if strings.TrimSpace(docsURL) == "" {
		docsURL = "https://docs.quantumauth.io"
	}
	u := strings.TrimSpace(username)
	if u == "" {
		u = "there"
	}

	uEsc := html.EscapeString(u)
	docsEsc := html.EscapeString(docsURL)
	logoEsc := html.EscapeString(strings.TrimSpace(logoURL))

	th := qaEmailTheme()

	return fmt.Sprintf(`<!doctype html>
<html lang="en">
  <body style="margin:0;padding:0;background:%s;font-family:Arial,Helvetica,sans-serif;">
    <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="background:%s;padding:28px 0;">
      <tr>
        <td align="center">

          <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="width:600px;max-width:600px;border-collapse:separate;border-spacing:0;">
            <tr>
              <td style="background:%s;border:1px solid %s;border-radius:16px;overflow:hidden;">

                <!-- Header -->
                <table role="presentation" width="100%%" cellspacing="0" cellpadding="0">
                  <tr>
                    <td style="padding:22px 24px;background:%s;">
                      <table role="presentation" cellspacing="0" cellpadding="0">
                        <tr>
                          <td style="vertical-align:middle;">
                           <img src="%s"
                             width="48"
                             height="48"
                             alt="QuantumAuth"
                             style="display:block;border:0;outline:none;text-decoration:none;">
                          </td>
                        </tr>
                      </table>

                      <div style="font-size:14px;color:%s;line-height:1.6;margin-top:10px;">
                        Hardware-aware, quantum-resistant authentication.
                      </div>
                    </td>
                  </tr>

                  <tr>
                    <td style="height:4px;line-height:4px;font-size:0;background:%s;"></td>
                  </tr>
                </table>

                <!-- Body -->
                <table role="presentation" width="100%%" cellspacing="0" cellpadding="0">
                  <tr>
                    <td style="padding:26px 24px;color:%s;background:%s;">
                      <div style="font-size:18px;font-weight:800;margin:0 0 10px 0;color:%s;">
                        Welcome, %s 👋
                      </div>

                      <div style="font-size:14px;line-height:1.7;color:%s;margin:0 0 14px 0;">
                        Your account is ready. You’ve joined <strong style="color:%s;">QuantumAuth</strong> — built to help you ship secure,
                        modern authentication without the usual friction.
                      </div>

                      <div style="font-size:14px;line-height:1.7;color:%s;margin:0 0 18px 0;">
                        Next step: read the docs and try the quickstart.
                      </div>

                      <!-- Button -->
                      <table role="presentation" cellspacing="0" cellpadding="0" style="margin:0 0 18px 0;">
                        <tr>
                          <td bgcolor="%s" style="border-radius:12px;">
                            <a href="%s"
                               style="display:inline-block;padding:12px 18px;color:#ffffff;text-decoration:none;font-size:14px;font-weight:800;border-radius:12px;">
                              Open QuantumAuth Docs
                            </a>
                          </td>
                        </tr>
                      </table>

                      <div style="font-size:12px;line-height:1.6;color:%s;">
                        If the button doesn’t work, copy and paste this link:<br/>
                        <a href="%s" style="color:%s;text-decoration:none;">%s</a>
                      </div>
                    </td>
                  </tr>
                </table>

                <!-- Footer -->
                <table role="presentation" width="100%%" cellspacing="0" cellpadding="0">
                  <tr>
                    <td style="padding:16px 24px;background:%s;color:%s;font-size:12px;line-height:1.6;border-top:1px solid %s;">
                      You received this email because a QuantumAuth account was created with this address.
                    </td>
                  </tr>
                </table>

              </td>
            </tr>

            <tr>
              <td style="padding:12px 0;text-align:center;color:%s;font-size:11px;line-height:1.4;">
                © %d QuantumAuth
              </td>
            </tr>
          </table>

        </td>
      </tr>
    </table>
  </body>
</html>`,
		th.Bg950, th.Bg950, // page bg
		th.Surface, th.Border, // card
		th.Bg900, logoEsc, // header bg + logo
		th.Muted,            // tagline
		th.Primary500,       // divider
		th.Text, th.Surface, // body container
		th.Text, uEsc, // title + name
		th.Muted, th.Text, // paragraph + QuantumAuth emphasis
		th.Muted,               // next step
		th.Primary600, docsEsc, // button
		th.Subtle, docsEsc, th.Accent500, docsEsc, // link
		th.Bg900, th.Subtle, th.Border, // footer
		th.Subtle, currentYear(), // copyright
	)
}

func WelcomeEmailText(username, docsURL string) string {
	if strings.TrimSpace(docsURL) == "" {
		docsURL = "https://docs.quantumauth.io"
	}

	u := strings.TrimSpace(username)
	if u == "" {
		u = "there"
	}

	return fmt.Sprintf(`QuantumAuth

Welcome, %s!

Your account is ready. You’ve joined QuantumAuth — built to help you ship secure, modern authentication without the usual friction.

Next step: read the docs and try the quickstart:
%s

If you didn’t create this account, you can ignore this email.

© %d QuantumAuth
`, u, docsURL, currentYear())
}

func currentYear() int {
	return time.Now().UTC().Year()
}
