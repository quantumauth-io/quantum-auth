package database

import (
	"context"
	"time"
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

type UpdateDeviceByIDInput struct {
	DeviceLabel *string
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
		return "", err
	}

	if err = resultRow.Scan(&id); err != nil {
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

			return nil, err
		}
		out = append(out, &d)
	}

	return out, rows.Err()
}

func (r *QuantumAuthRepository) UpdateDeviceByID(ctx context.Context, deviceID string, in UpdateDeviceByIDInput) (*Device, error) {
	const query = `
		UPDATE devices
		SET
			device_label = COALESCE($2, device_label)
		WHERE device_id = $1
		RETURNING device_id, user_id, device_label, tpm_public_key, pq_public_key, created_at;
	`

	var d Device
	row, err := r.db.QueryRow(ctx, query, deviceID, in.DeviceLabel)
	if err != nil {

		return nil, err
	}

	if err := row.Scan(
		&d.ID,
		&d.UserID,
		&d.DeviceLabel,
		&d.TPMPublicKey,
		&d.PQPublicKey,
		&d.CreatedAt,
	); err != nil {

		return nil, err
	}

	return &d, nil
}
