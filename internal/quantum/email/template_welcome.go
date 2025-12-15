package email

import (
	"fmt"
	"html"
	"strings"
	"time"
)

// WelcomeEmailHTML returns a simple, nice-looking HTML email.
// Keep it table-based for best compatibility across email clients.
func WelcomeEmailHTML(username, docsURL string) string {
	if strings.TrimSpace(docsURL) == "" {
		docsURL = "https://docs.quantumauth.io"
	}

	u := strings.TrimSpace(username)
	if u == "" {
		u = "there"
	}

	// Escape any user-provided data to avoid HTML injection.
	uEsc := html.EscapeString(u)
	docsEsc := html.EscapeString(docsURL)

	return fmt.Sprintf(`<!doctype html>
<html lang="en">
  <body style="margin:0;padding:0;background:#f5f7fb;font-family:Arial,Helvetica,sans-serif;">
    <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="background:#f5f7fb;padding:24px 0;">
      <tr>
        <td align="center">
          <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,0.06);">
            <!-- Header -->
            <tr>
              <td style="background:#020618;padding:28px 24px;text-align:center;">
                <div style="color:#ffffff;font-size:26px;font-weight:700;letter-spacing:0.3px;">
                  QuantumAuth
                </div>
              </td>
            </tr>

            <!-- Body -->
            <tr>
              <td style="padding:28px 24px;color:#0f172a;">
                <div style="font-size:18px;font-weight:700;margin:0 0 8px 0;">Welcome, %s 👋</div>

                <div style="font-size:14px;line-height:1.6;color:#334155;margin:0 0 16px 0;">
                  Your account is ready. You’ve joined <strong>QuantumAuth</strong> — a platform designed to help you build
                  and use secure, modern authentication.
                </div>

                <div style="font-size:14px;line-height:1.6;color:#334155;margin:0 0 18px 0;">
                  Next step: read the docs and try the quickstart.
                </div>

                <!-- Button -->
                <table role="presentation" cellspacing="0" cellpadding="0" style="margin:0 0 18px 0;">
                  <tr>
                    <td style="border-radius:10px;" bgcolor="#020618">
                      <a href="%s"
                         style="display:inline-block;padding:12px 18px;color:#ffffff;text-decoration:none;font-size:14px;font-weight:700;border-radius:10px;">
                        Open QuantumAuth Docs
                      </a>
                    </td>
                  </tr>
                </table>

                <div style="font-size:12px;line-height:1.6;color:#64748b;">
                  If the button doesn’t work, copy and paste this link:<br/>
                  <a href="%s" style="color:#1f5eff;text-decoration:none;">%s</a>
                </div>
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="padding:16px 24px;background:#f8fafc;color:#64748b;font-size:12px;line-height:1.5;">
                You received this email because a QuantumAuth account was created with this address.
              </td>
            </tr>
          </table>

          <div style="width:600px;max-width:600px;color:#94a3b8;font-size:11px;line-height:1.4;padding:12px 0;text-align:center;">
            © %d QuantumAuth
          </div>
        </td>
      </tr>
    </table>
  </body>
</html>`, uEsc, docsEsc, docsEsc, docsEsc, currentYear())
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

Your account is ready. You’ve joined QuantumAuth — a platform designed to help you build and use secure, modern authentication.

Next step: read the docs and try the quickstart:
%s

If you didn’t create this account, you can ignore this email.

© %d QuantumAuth
`, u, docsURL, currentYear())
}

// keep this tiny and dependency-free
func currentYear() int {
	return time.Now().UTC().Year()
}
