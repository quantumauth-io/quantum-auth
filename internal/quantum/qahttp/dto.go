package qahttp

import (
	"encoding/json"
	"time"

	"github.com/quantumauth-io/quantum-auth/internal/quantum/database"
)

// ---------- Requests / Responses ----------

type authChallengeRequest struct {
	DeviceID string `json:"device_id" binding:"required"`
	AppID    string `json:"app_id" binding:"required"`
}

type authChallengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	Nonce       int64     `json:"nonce"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type authVerifyRequest struct {
	Method  string            `json:"method" binding:"required,oneof=GET POST PUT PATCH DELETE"`
	Path    string            `json:"path" binding:"required"`
	Headers map[string]string `json:"headers" binding:"required"`
}

// Response: omitempty is good here to avoid leaking user_id when not authenticated.
type authVerifyResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"user_id,omitempty"`
}

type Device struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	TPMPublicKey string    `json:"tpm_public_key"`
	PQPublicKey  string    `json:"pq_public_key"`
	CreatedAt    time.Time `json:"created_at"`
	IsRevoked    bool      `json:"is_revoked"`
}

type SignedMessage struct {
	ChallengeID string `json:"challenge_id" binding:"required"`
	DeviceID    string `json:"device_id" binding:"required"`
	Nonce       int64  `json:"nonce" binding:"required"`
	Purpose     string `json:"purpose" binding:"required,oneof=login secure_ping verify_request"`
}

// ---------- Device registration ----------

// Option A (recommended): keep this endpoint purely password-backed, no omitempty.
type registerDeviceRequest struct {
	UserEmail    string `json:"user_email" binding:"required,email"`
	PasswordB64  string `json:"password_b64" binding:"required,min=8"`
	DeviceLabel  string `json:"device_label" binding:"required,min=1,max=64"`
	TPMPublicKey string `json:"tpm_public_key" binding:"required,min=32"` // adjust min to your encoding
	PQPublicKey  string `json:"pq_public_key" binding:"required,min=32"`
}

type registerDeviceResponse struct {
	DeviceID string `json:"device_id"`
	UserID   string `json:"user_id"`
}

type SignupRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Username    string `json:"username" binding:"omitempty,min=3,max=32"`
	PasswordB64 string `json:"password_b64" binding:"required,min=8"`
	FirstName   string `json:"firstName" binding:"omitempty,max=64"`
	LastName    string `json:"lastName" binding:"omitempty,max=64"`
}

type loginMessage struct {
	UserID   string `json:"user_id"`
	DeviceID string `json:"device_id"`
	Purpose  string `json:"purpose"`
	TS       int64  `json:"ts"`
}

type meRequest struct {
	Email       string `json:"email" binding:"required,email"`
	PasswordB64 string `json:"password_b64" binding:"required,min=8"`
}

type meResponse struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	FirstName string    `json:"first_name,omitempty"`
	LastName  string    `json:"last_name,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type updateMeRequest struct {
	Email     *string `json:"email,omitempty"`
	Username  *string `json:"username,omitempty"`
	FirstName *string `json:"first_name,omitempty"`
	LastName  *string `json:"last_name,omitempty"`
}
type fullLoginRequest struct {
	UserID       string `json:"user_id" binding:"required"`
	DeviceID     string `json:"device_id" binding:"required"`
	PasswordB64  string `json:"password_b64" binding:"required,min=8"`
	MessageB64   string `json:"message_b64" binding:"omitempty"`
	TPMSignature string `json:"tpm_signature" binding:"omitempty"`
	PQSignature  string `json:"pq_signature" binding:"omitempty"`
}

type fullLoginResponse struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"user_id,omitempty"`
	DeviceID      string `json:"device_id,omitempty"`
}

type newsletterRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type newsletterResponse struct {
	NewsletterID string `json:"newsletter_id,omitempty"`
	Email        string `json:"email"`
	Subscribed   bool   `json:"subscribed"`
}

type deviceResponse struct {
	DeviceID     string    `json:"device_id"`
	UserID       string    `json:"user_id"`
	DeviceLabel  *string   `json:"device_label,omitempty"`
	TPMPublicKey string    `json:"tpm_public_key"`
	PQPublicKey  string    `json:"pq_public_key"`
	CreatedAt    time.Time `json:"created_at"`
}

type updateDeviceRequest struct {
	DeviceLabel *string `json:"device_label,omitempty"`
}

type createAppRequest struct {
	Name           string  `json:"name" binding:"required,min=2,max=255"`
	Description    string  `json:"description,omitempty"`
	Domain         string  `json:"domain" binding:"required"`
	BackendHost    string  `json:"backend_host" binding:"required,min=1,max=255"`
	PQPublicKeyB64 *string `json:"pq_public_key_b64,omitempty"`
}

type updateAppRequest struct {
	Name           *string `json:"name,omitempty"`
	Description    *string `json:"description,omitempty"`
	Domain         *string `json:"domain,omitempty"`
	BackendHost    *string `json:"backend_host,omitempty"`
	Tier           *string `json:"tier,omitempty"`
	PQPublicKeyB64 *string `json:"pq_public_key_b64,omitempty"`
}

type appResponse struct {
	AppID       string `json:"app_id"`
	OwnerUserID string `json:"owner_user_id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Domain      string `json:"domain"`
	BackendHost string `json:"backend_host"`
	Tier        string `json:"tier"`

	Verified          bool   `json:"verified"`
	VerificationToken string `json:"verification_token"`

	PQPublicKeyB64 *string `json:"pq_public_key_b64,omitempty"`

	LastVerifiedAt *time.Time `json:"last_verified_at,omitempty"`
	LastCheckedAt  *time.Time `json:"last_checked_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}
type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}
type createAppResponse struct {
	App appResponse `json:"app"`
	DNS struct {
		Records []DNSRecord `json:"records"`
	} `json:"dns"`
}

type productResponse struct {
	ProductID string `json:"product_id"`
	AppID     string `json:"app_id"`

	Type        database.ProductType `json:"type"`
	Name        string               `json:"name"`
	Description *string              `json:"description,omitempty"`
	Slug        string               `json:"slug"`

	PriceAmount   string `json:"price_amount"`
	PriceCurrency string `json:"price_currency"`

	BillingIntervalCount *int                          `json:"billing_interval_count,omitempty"`
	BillingIntervalUnit  *database.BillingIntervalUnit `json:"billing_interval_unit,omitempty"`
	BillingAnchor        *string                       `json:"billing_anchor,omitempty"`

	StockQuantity *int64 `json:"stock_quantity,omitempty"`
	SoldCount     int64  `json:"sold_count"`

	IsActive bool            `json:"is_active"`
	Metadata json.RawMessage `json:"metadata"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toProductResponse(p *database.Product) productResponse {
	return productResponse{
		ProductID: p.ProductID,
		AppID:     p.AppID,

		Type:        p.Type,
		Name:        p.Name,
		Description: p.Description,
		Slug:        p.Slug,

		PriceAmount:   p.PriceAmount,
		PriceCurrency: p.PriceCurrency,

		BillingIntervalCount: p.BillingIntervalCount,
		BillingIntervalUnit:  p.BillingIntervalUnit,
		BillingAnchor:        p.BillingAnchor,

		StockQuantity: p.StockQuantity,
		SoldCount:     p.SoldCount,

		IsActive: p.IsActive,
		Metadata: p.Metadata,

		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

type createProductRequest struct {
	Type        database.ProductType `json:"type" binding:"required,oneof=item service subscription"`
	Name        string               `json:"name" binding:"required,min=1,max=160"`
	Description *string              `json:"description"`
	Slug        string               `json:"slug" binding:"required,min=1,max=200"`

	PriceAmount   string `json:"price_amount" binding:"required"` // keep as string; validate in service later
	PriceCurrency string `json:"price_currency"`                  // optional; defaults to USD

	// subscription only
	BillingIntervalCount *int                          `json:"billing_interval_count"`
	BillingIntervalUnit  *database.BillingIntervalUnit `json:"billing_interval_unit"`
	BillingAnchor        *string                       `json:"billing_anchor"`

	// item inventory
	StockQuantity *int64 `json:"stock_quantity"`

	Metadata json.RawMessage `json:"metadata"`
}

type updateProductRequest struct {
	Type *database.ProductType `json:"type" binding:"omitempty,oneof=item service subscription"`
	Name *string               `json:"name" binding:"omitempty,min=1,max=160"`
	// For patch semantics, description nulling is tricky; simplest: allow setting to null explicitly.
	Description *string `json:"description"`
	Slug        *string `json:"slug" binding:"omitempty,min=1,max=200"`

	PriceAmount   *string `json:"price_amount"`
	PriceCurrency *string `json:"price_currency"`

	BillingIntervalCount *int                          `json:"billing_interval_count"`
	BillingIntervalUnit  *database.BillingIntervalUnit `json:"billing_interval_unit"`
	BillingAnchor        *string                       `json:"billing_anchor"`

	StockQuantity *int64 `json:"stock_quantity"`

	IsActive *bool `json:"is_active"`

	Metadata *json.RawMessage `json:"metadata"`
}
