package database

import (
	"context"
	"time"
)

type App struct {
	AppID             string
	OwnerUserID       string
	Name              string
	Description       string
	Domain            string
	Tier              string // "free" | "premium"
	VerificationToken string
	Verified          bool
	LastVerifiedAt    *time.Time
	LastCheckedAt     *time.Time
	PQPublicKey       []byte
	CreatedAt         time.Time
	UpdatedAt         time.Time
	BackendHost       string
}

type CreateAppInput struct {
	OwnerUserID       string
	Name              string
	Description       string
	Domain            string
	BackendHost       string
	Tier              string // optional; default "free"
	VerificationToken string
	PQPublicKey       []byte
}

type UpdateAppByIDInput struct {
	Name        *string
	Description *string
	Domain      *string
	BackendHost *string
	Tier        *string

	PQPublicKey *[]byte

	// When domain changes: reset verification + rotate token (recommended)
	ResetVerification bool
	NewToken          *string
}

type SetAppVerificationInput struct {
	AppID          string
	Verified       bool
	LastCheckedAt  time.Time
	LastVerifiedAt *time.Time
}

func (r *QuantumAuthRepository) CreateApp(ctx context.Context, in CreateAppInput) (*App, error) {
	const q = `
		INSERT INTO apps (
			owner_user_id, name, description, domain, tier, verification_token, pq_public_key, backend_host
		)
		VALUES ($1, $2, $3, $4, COALESCE(NULLIF($5, ''), 'free'), $6, $7, $8)
		RETURNING
			app_id, owner_user_id, name, description, domain, tier,
			verification_token, verified, last_verified_at, last_checked_at,
			pq_public_key,
			created_at, updated_at, backend_host; 
	`

	var a App
	row, err := r.db.QueryRow(ctx, q,
		in.OwnerUserID,
		in.Name,
		in.Description,
		in.Domain,
		in.Tier,
		in.VerificationToken,
		in.PQPublicKey,
		in.BackendHost,
	)
	if err != nil {
		return nil, err
	}

	if err := row.Scan(
		&a.AppID, &a.OwnerUserID, &a.Name, &a.Description, &a.Domain, &a.Tier,
		&a.VerificationToken, &a.Verified, &a.LastVerifiedAt, &a.LastCheckedAt,
		&a.PQPublicKey,
		&a.CreatedAt, &a.UpdatedAt, &a.BackendHost,
	); err != nil {

		return nil, err
	}

	return &a, nil
}

func (r *QuantumAuthRepository) GetAppsByUserID(ctx context.Context, userID string) ([]*App, error) {
	const q = `
	SELECT
		app_id, owner_user_id, name, description, domain, tier,
		verification_token, verified, last_verified_at, last_checked_at,
		pq_public_key,
		created_at, updated_at, backend_host
	FROM apps
	WHERE owner_user_id = $1
	ORDER BY created_at ASC;
`

	rows, err := r.db.Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*App
	for rows.Next() {
		var a App
		if err := rows.Scan(
			&a.AppID, &a.OwnerUserID, &a.Name, &a.Description, &a.Domain, &a.Tier,
			&a.VerificationToken, &a.Verified, &a.LastVerifiedAt, &a.LastCheckedAt,
			&a.PQPublicKey,
			&a.CreatedAt, &a.UpdatedAt, &a.BackendHost,
		); err != nil {

			return nil, err
		}
		out = append(out, &a)
	}

	return out, rows.Err()
}

func (r *QuantumAuthRepository) GetAppByID(ctx context.Context, appID string) (*App, error) {
	const q = `
	SELECT
		app_id, owner_user_id, name, description, domain, tier,
		verification_token, verified, last_verified_at, last_checked_at,
		pq_public_key,
		created_at, updated_at, backend_host
	FROM apps
	WHERE app_id = $1
	ORDER BY created_at ASC;
`

	var a App
	row, err := r.db.QueryRow(ctx, q, appID)
	if err != nil {

		return nil, err
	}

	if err := row.Scan(
		&a.AppID, &a.OwnerUserID, &a.Name, &a.Description, &a.Domain, &a.Tier,
		&a.VerificationToken, &a.Verified, &a.LastVerifiedAt, &a.LastCheckedAt,
		&a.PQPublicKey,
		&a.CreatedAt, &a.UpdatedAt, &a.BackendHost,
	); err != nil {

		return nil, err
	}

	return &a, nil
}

func (r *QuantumAuthRepository) UpdateAppByID(ctx context.Context, appID string, in UpdateAppByIDInput) (*App, error) {
	const q = `
		UPDATE apps
		SET
			name = COALESCE($2, name),
			description = COALESCE($3, description),
			domain = COALESCE($4, domain),
			backend_host = COALESCE($9, backend_host),
			tier = COALESCE($5, tier),
			pq_public_key = COALESCE($6, pq_public_key),
			verified = CASE WHEN $7 THEN FALSE ELSE verified END,
			verification_token = CASE WHEN $7 THEN COALESCE($8, verification_token) ELSE verification_token END,
			last_verified_at = CASE WHEN $7 THEN NULL ELSE last_verified_at END,
			last_checked_at = CASE WHEN $7 THEN NULL ELSE last_checked_at END,
			updated_at = now()
		WHERE app_id = $1
		RETURNING
			app_id, owner_user_id, name, description, domain, tier,
			verification_token, verified, last_verified_at, last_checked_at,
			pq_public_key,
			created_at, updated_at, backend_host;
	`

	// COALESCE expects NULL when we don't want to touch it.
	// If in.PQPublicKey == nil => pass nil
	// else pass the []byte value
	var pq any = nil
	if in.PQPublicKey != nil {
		pq = *in.PQPublicKey
	}

	var a App
	row, err := r.db.QueryRow(ctx, q,
		appID,
		in.Name,
		in.Description,
		in.Domain,
		in.Tier,
		pq,
		in.ResetVerification,
		in.NewToken,
		in.BackendHost,
	)
	if err != nil {

		return nil, err
	}

	if err := row.Scan(
		&a.AppID, &a.OwnerUserID, &a.Name, &a.Description, &a.Domain, &a.Tier,
		&a.VerificationToken, &a.Verified, &a.LastVerifiedAt, &a.LastCheckedAt,
		&a.PQPublicKey,
		&a.CreatedAt, &a.UpdatedAt, &a.BackendHost,
	); err != nil {

		return nil, err
	}

	return &a, nil
}

func (r *QuantumAuthRepository) SetAppVerification(ctx context.Context, in SetAppVerificationInput) error {
	const q = `
		UPDATE apps
		SET
			verified = $2,
			last_checked_at = $3,
			last_verified_at = $4,
			updated_at = now()
		WHERE app_id = $1;
	`

	_, err := r.db.Exec(ctx, q, in.AppID, in.Verified, in.LastCheckedAt, in.LastVerifiedAt)
	return err
}

func (r *QuantumAuthRepository) GetAppsForVerificationScan(ctx context.Context, limit int) ([]*App, error) {
	const q = `
		SELECT
			app_id, owner_user_id, name, description, domain, tier,
			verification_token, verified, last_verified_at, last_checked_at,
			created_at, updated_at, backend_host
		FROM apps
		ORDER BY COALESCE(last_checked_at, 'epoch') ASC
		LIMIT $1;
	`

	rows, err := r.db.Query(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*App
	for rows.Next() {
		var a App
		if err := rows.Scan(
			&a.AppID, &a.OwnerUserID, &a.Name, &a.Description, &a.Domain, &a.Tier,
			&a.VerificationToken, &a.Verified, &a.LastVerifiedAt, &a.LastCheckedAt,
			&a.CreatedAt, &a.UpdatedAt, &a.BackendHost,
		); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}
