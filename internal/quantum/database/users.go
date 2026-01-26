package database

import (
	"context"
	"time"
)

// User represents a row in the users table.
type User struct {
	ID           string
	Username     string
	Email        string
	PasswordHash string
	FirstName    string
	LastName     string
	CreatedAt    time.Time
}

type CreateUserInput struct {
	Email     string
	Password  string
	Username  string
	FirstName string
	LastName  string
}
type UpdateUserByIDInput struct {
	Email     *string
	Username  *string
	FirstName *string
	LastName  *string
}

// CreateUser creates a new user with the given email, password, and username.
func (r *QuantumAuthRepository) CreateUser(ctx context.Context, in CreateUserInput) (string, error) {
	const query = `
		INSERT INTO users (email, password_hash, username, first_name, last_name)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING user_id;
	`

	var id string
	resultRow, err := r.db.QueryRow(ctx, query,
		in.Email,
		in.Password,
		in.Username,
		in.FirstName,
		in.LastName,
	)
	if err != nil {

		return "", err
	}
	err = resultRow.Scan(&id)
	if err != nil {

		return "", err
	}

	return id, nil
}

// GetUserByID returns a user by user_id.
func (r *QuantumAuthRepository) GetUserByID(ctx context.Context, id string) (*User, error) {
	const query = `
		SELECT user_id, username, email, password_hash, first_name, last_name, created_at
		FROM users
		WHERE user_id = $1;
	`

	var u User
	resultRow, err := r.db.QueryRow(ctx, query, id)
	if err != nil {

		return nil, err
	}

	err = resultRow.Scan(
		&u.ID,
		&u.Username,
		&u.Email,
		&u.PasswordHash,
		&u.FirstName,
		&u.LastName,
		&u.CreatedAt,
	)
	if err != nil {

		return nil, err
	}

	return &u, nil
}

// GetUserByEmail returns a user by email.
func (r *QuantumAuthRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	const query = `
		SELECT user_id, username, email, password_hash, first_name, last_name, created_at
		FROM users
		WHERE email = $1;
	`

	var u User
	resultRow, err := r.db.QueryRow(ctx, query, email)
	if err != nil {

		return nil, err
	}

	err = resultRow.Scan(
		&u.ID,
		&u.Username,
		&u.Email,
		&u.PasswordHash,
		&u.FirstName,
		&u.LastName,
		&u.CreatedAt,
	)
	if err != nil {

		return nil, err
	}

	return &u, nil
}

func (r *QuantumAuthRepository) UpdateUserByID(ctx context.Context, id string, in UpdateUserByIDInput) (*User, error) {
	const query = `
		UPDATE users
		SET
			email = COALESCE($2, email),
			username = COALESCE($3, username),
			first_name = COALESCE($4, first_name),
			last_name = COALESCE($5, last_name)
		WHERE user_id = $1
		RETURNING user_id, username, email, password_hash, first_name, last_name, created_at;
	`

	var u User
	row, err := r.db.QueryRow(ctx, query,
		id,
		in.Email,
		in.Username,
		in.FirstName,
		in.LastName,
	)
	if err != nil {

		return nil, err
	}

	if err := row.Scan(
		&u.ID,
		&u.Username,
		&u.Email,
		&u.PasswordHash,
		&u.FirstName,
		&u.LastName,
		&u.CreatedAt,
	); err != nil {

		return nil, err
	}

	return &u, nil
}
