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

func (r *Repository) GetAllUsers() ([]User, error) {
	query := `
		SELECT id, email, first_name, last_name, country, language, is_active, created_at, updated_at
		FROM users 
		WHERE is_active = true`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Email, &user.FirstName, &user.LastName,
			&user.Country, &user.Language, &user.IsActive, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate rows: %w", err)
	}

	return users, nil
}

func (r *Repository) UpdateUser(user *User) error {
	query := `
		UPDATE users 
		SET email = $1, first_name = $2, last_name = $3, 
		    country = $4, language = $5, updated_at = $6
		WHERE id = $7`

	_, err := r.db.Exec(query, user.Email, user.FirstName,
		user.LastName, user.Country, user.Language,
		time.Now(), user.ID)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
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
