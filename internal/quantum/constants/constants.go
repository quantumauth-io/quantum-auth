package constants

const (
	MlDSA65PublicKeyLen    = 1952
	ApiBase                = "/quantum-auth/v1"
	ClientLoginPurpose     = "client-login"
	EmailFromName          = "QuantumAuth"
	EmailFromAddress       = "noreply@quantumauth.io"
	EmailWelcomeSubject    = "Welcome to QuantumAuth"
	EmailLogoUrl           = "https://quantumauth.io/logo.png"
	EmailDocsUrl           = "https://quantumauth.io/docs"
	QADNSRecordName        = "_quantumauth."
	QADNSRecordType        = "TXT"
	QADNSRecordValuePrefix = "qa-verify="
	QAFreeTier             = "free"
	QAAuthHeaderPrefix     = "QuantumAuth "
	QAHeaderSigVersion     = "1"
)
