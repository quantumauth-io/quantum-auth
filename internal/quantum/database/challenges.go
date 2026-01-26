package database

import (
	"context"
	"errors"
	"time"
)

// Challenge represents a challenge issued for authentication.
type Challenge struct {
	ID        string
	DeviceID  string
	Nonce     int64
	ExpiresAt time.Time
	CreatedAt time.Time
}

type CreateChallengeInput struct {
	DeviceID  string
	AppID     string
	Nonce     int64
	ExpiresAt time.Time
}

var ErrChallengeNotFoundOrAlreadyUsed = errors.New("challenge not found or already used")

// CreateChallenge inserts a new challenge into the database.
func (r *QuantumAuthRepository) CreateChallenge(ctx context.Context, in *CreateChallengeInput) (string, error) {
	const query = `
		INSERT INTO auth_challenges (device_id, expires_at, app_id)
		VALUES ($1, $2, $3)
		RETURNING challenge_id;
	`

	var id string
	resultRow, err := r.db.QueryRow(ctx, query,
		in.DeviceID,
		in.ExpiresAt,
		in.AppID,
	)
	if err != nil {
		return "", err
	}

	if err := resultRow.Scan(&id); err != nil {
		return "", err
	}

	return id, nil
}

// GetChallenge retrieves a challenge by its ID.
func (r *QuantumAuthRepository) GetChallenge(ctx context.Context, challengeID string) (*Challenge, error) {
	const query = `
		SELECT challenge_id, device_id, expires_at, created_at
		FROM auth_challenges
		WHERE challenge_id = $1;
	`

	var c Challenge
	resultRow, err := r.db.QueryRow(ctx, query, challengeID)
	if err != nil {

		return nil, err
	}

	err = resultRow.Scan(
		&c.ID,
		&c.DeviceID,
		&c.Nonce,
		&c.ExpiresAt,
		&c.CreatedAt,
	)
	if err != nil {

		return nil, err
	}

	return &c, nil
}

// DeleteChallenge removes a challenge once it has been consumed.
func (r *QuantumAuthRepository) ConsumeChallenge(ctx context.Context, challengeID, deviceID, appID string) error {
	const query = `
		DELETE FROM auth_challenges
		WHERE challenge_id = $1
		  AND device_id    = $2
		  AND app_id       = $3
		  AND expires_at   > now();
	`

	ct, err := r.db.Exec(ctx, query, challengeID, deviceID, appID)
	if err != nil {
		return err
	}

	rows, err := ct.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrChallengeNotFoundOrAlreadyUsed
	}

	return nil
}

// DeleteExpiredChallenges removes all outdated challenges.
func (r *QuantumAuthRepository) DeleteExpiredChallenges(ctx context.Context, now time.Time) (int64, error) {
	const query = `
		DELETE FROM auth_challenges
		WHERE expires_at < $1;
	`

	result, err := r.db.Exec(ctx, query, now)
	if err != nil {

		return 0, err
	}

	tag, err := result.RowsAffected()
	if err != nil {

		return 0, err
	}

	return tag, nil
}
