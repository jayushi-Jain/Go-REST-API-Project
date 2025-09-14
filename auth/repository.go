package auth

import (
	"database/sql"
	"fmt"
	"time"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateUser(user *User) error {
	query := `
		INSERT INTO users (email, password_hash, first_name, last_name, country, language, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id`

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	user.IsActive = true

	if user.Language == "" {
		user.Language = "en"
	}

	err := r.db.QueryRow(query, user.Email, user.Password, user.FirstName,
		user.LastName, user.Country, user.Language, user.IsActive,
		user.CreatedAt, user.UpdatedAt).Scan(&user.ID)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

func (r *Repository) GetUserByEmail(email string) (*User, error) {
	user := &User{}
	query := `
		SELECT id, email, password_hash, first_name, last_name, country, 
		       language, is_active, created_at, updated_at
		FROM users 
		WHERE email = $1 AND is_active = true`

	err := r.db.QueryRow(query, email).Scan(
		&user.ID, &user.Email, &user.Password, &user.FirstName,
		&user.LastName, &user.Country, &user.Language, &user.IsActive,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

func (r *Repository) GetUserByID(id int) (*User, error) {
	user := &User{}
	query := `
		SELECT id, email, password_hash, first_name, last_name, country, 
		       language, is_active, created_at, updated_at
		FROM users 
		WHERE id = $1 AND is_active = true`

	err := r.db.QueryRow(query, id).Scan(
		&user.ID, &user.Email, &user.Password, &user.FirstName,
		&user.LastName, &user.Country, &user.Language, &user.IsActive,
		&user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}
