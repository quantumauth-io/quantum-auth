package database

import (
	"context"
	"time"

	"github.com/quantumauth-io/quantum-go-utils/log"
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
	Nonce     int64
	ExpiresAt time.Time
}

// CreateChallenge inserts a new challenge into the database.
func (r *QuantumAuthRepository) CreateChallenge(ctx context.Context, in *CreateChallengeInput) (string, error) {
	const query = `
		INSERT INTO auth_challenges (device_id, expires_at)
		VALUES ($1, $2)
		RETURNING challenge_id;
	`

	var id string
	resultRow, err := r.db.QueryRow(ctx, query,
		in.DeviceID,
		in.ExpiresAt,
	)
	if err != nil {
		log.Error("Error creating challenge", "error", err)
		return "", err
	}

	if err := resultRow.Scan(&id); err != nil {
		log.Error("Error creating challenge", "error", err)
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
		log.Error("Error getting challenge", "error", err)
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
		log.Error("Error getting challenge", "error", err)
		return nil, err
	}

	return &c, nil
}

// DeleteChallenge removes a challenge once it has been consumed.
func (r *QuantumAuthRepository) DeleteChallenge(ctx context.Context, challengeID string) error {

	log.Info("deleting challenge", "challenge_id", challengeID)
	const query = `
		DELETE FROM auth_challenges
		WHERE challenge_id = $1;
	`

	_, err := r.db.Exec(ctx, query, challengeID)
	if err != nil {
		log.Error("Error deleting challenge", "error", err)
	}

	return err
}

// DeleteExpiredChallenges removes all outdated challenges.
func (r *QuantumAuthRepository) DeleteExpiredChallenges(ctx context.Context, now time.Time) (int64, error) {
	const query = `
		DELETE FROM auth_challenges
		WHERE expires_at < $1;
	`

	result, err := r.db.Exec(ctx, query, now)
	if err != nil {
		log.Error("Error deleting expired challenges", "error", err)
		return 0, err
	}

	tag, err := result.RowsAffected()
	if err != nil {
		log.Error("Error deleting expired challenges", "error", err)
	}

	return tag, nil
}
