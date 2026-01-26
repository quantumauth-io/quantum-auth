package database

import (
	"context"
	"time"
)

// NewsletterSubscription represents a row in the newsletter table.
type NewsletterSubscription struct {
	ID         string
	Email      string
	Subscribed bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type SubscribeNewsletterInput struct {
	Email string
}

// SubscribeNewsletter creates or re-subscribes an email.
// - If email is new: inserts a row subscribed=true
// - If email exists: sets subscribed=true (re-subscribe) and bumps updated_at via trigger
func (r *QuantumAuthRepository) SubscribeNewsletter(ctx context.Context, in SubscribeNewsletterInput) (string, error) {
	const query = `
		INSERT INTO newsletter (email, subscribed)
		VALUES ($1, true)
		ON CONFLICT (email)
		DO UPDATE SET subscribed = EXCLUDED.subscribed
		RETURNING newsletter_id;
	`

	var id string
	row, err := r.db.QueryRow(ctx, query, in.Email)
	if err != nil {
		return "", err
	}

	if err := row.Scan(&id); err != nil {
		return "", err
	}

	return id, nil
}

type UnsubscribeNewsletterInput struct {
	Email string
}

// UnsubscribeNewsletter sets subscribed=false for the given email.
// If the email doesn't exist, it returns nil (no row found) as an error from Scan.
func (r *QuantumAuthRepository) UnsubscribeNewsletter(ctx context.Context, in UnsubscribeNewsletterInput) (string, error) {
	const query = `
		UPDATE newsletter
		SET subscribed = false
		WHERE email = $1
		RETURNING newsletter_id;
	`

	var id string
	row, err := r.db.QueryRow(ctx, query, in.Email)
	if err != nil {

		return "", err
	}

	if err := row.Scan(&id); err != nil {

		return "", err
	}

	return id, nil
}

// GetNewsletterByEmail returns a newsletter subscription row by email.
func (r *QuantumAuthRepository) GetNewsletterByEmail(ctx context.Context, email string) (*NewsletterSubscription, error) {
	const query = `
		SELECT newsletter_id, email, subscribed, created_at, updated_at
		FROM newsletter
		WHERE email = $1;
	`

	var n NewsletterSubscription
	row, err := r.db.QueryRow(ctx, query, email)
	if err != nil {

		return nil, err
	}

	if err := row.Scan(
		&n.ID,
		&n.Email,
		&n.Subscribed,
		&n.CreatedAt,
		&n.UpdatedAt,
	); err != nil {

		return nil, err
	}

	return &n, nil
}

// IsNewsletterSubscribed is a small helper to check if an email is subscribed.
// Returns (false, nil) if no row exists.
func (r *QuantumAuthRepository) IsNewsletterSubscribed(ctx context.Context, email string) (bool, error) {
	const query = `
		SELECT subscribed
		FROM newsletter
		WHERE email = $1;
	`

	var subscribed bool
	row, err := r.db.QueryRow(ctx, query, email)
	if err != nil {

		return false, err
	}

	if err := row.Scan(&subscribed); err != nil {

		return false, err
	}

	return subscribed, nil
}
