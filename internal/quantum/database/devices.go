package database

import (
	"context"
	"fmt"
	"time"

	"github.com/quantumauth-io/quantum-go-utils/log"
)

// Device represents a row in the devices table.
type Device struct {
	ID           string
	UserID       string
	DeviceLabel  *string
	TPMPublicKey string
	PQPublicKey  string
	CreatedAt    time.Time
}

type CreateDeviceInput struct {
	UserID       string
	DeviceLabel  string
	TPMPublicKey string
	PQPublicKey  string
}

// CreateDevice creates a new device for a given user.
func (r *QuantumAuthRepository) CreateDevice(ctx context.Context, in *CreateDeviceInput) (string, error) {
	const query = `
		INSERT INTO devices (user_id, device_label, tpm_public_key, pq_public_key)
		VALUES ($1, $2, $3, $4)
		RETURNING device_id;
	`

	var id string
	resultRow, err := r.db.QueryRow(ctx, query,
		in.UserID,
		in.DeviceLabel,
		in.TPMPublicKey,
		in.PQPublicKey,
	)
	if err != nil {
		log.Error("Error creating device", "error", err)
		return "", err
	}

	if err = resultRow.Scan(&id); err != nil {
		log.Error("Error creating device", "error", err)
		return "", err
	}

	return id, nil
}

// GetDeviceByID returns a device by device_id.
func (r *QuantumAuthRepository) GetDeviceByID(ctx context.Context, deviceID string) (*Device, error) {
	const query = `
		SELECT device_id, user_id, device_label, tpm_public_key, pq_public_key, created_at
		FROM devices
		WHERE device_id = $1;
	`

	var d Device
	resultRow, err := r.db.QueryRow(ctx, query, deviceID)
	if err != nil {
		log.Error("db error", "type", fmt.Sprintf("%T", err), "err", fmt.Sprintf("%+v", err))
		log.Error("Error getting device", "error", err, "device_id", deviceID)
		return nil, err
	}

	err = resultRow.Scan(
		&d.ID,
		&d.UserID,
		&d.DeviceLabel,
		&d.TPMPublicKey,
		&d.PQPublicKey,
		&d.CreatedAt,
	)
	if err != nil {
		log.Error("Error getting device", "error", err)
		return nil, err
	}

	return &d, nil
}

// GetDevicesByUserID returns all devices belonging to a user.
func (r *QuantumAuthRepository) GetDevicesByUserID(ctx context.Context, userID string) ([]*Device, error) {
	const query = `
		SELECT device_id, user_id, device_label, tpm_public_key, pq_public_key, created_at
		FROM devices
		WHERE user_id = $1
		ORDER BY created_at ASC;
	`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		log.Error("Error getting devices", "error", err)
		return nil, err
	}
	defer rows.Close()

	var out []*Device

	for rows.Next() {
		var d Device
		if err := rows.Scan(
			&d.ID,
			&d.UserID,
			&d.DeviceLabel,
			&d.TPMPublicKey,
			&d.PQPublicKey,
			&d.CreatedAt,
		); err != nil {
			log.Error("Error scanning devices", "error", err)
			return nil, err
		}
		out = append(out, &d)
	}

	return out, rows.Err()
}
