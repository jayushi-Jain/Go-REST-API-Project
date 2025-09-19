package auth

import (
	"fmt"
)

type Service struct {
	repo       *Repository
	jwtService *JWTService
}

func NewService(repo *Repository, jwtService *JWTService) *Service {
	return &Service{
		repo:       repo,
		jwtService: jwtService,
	}
}

func (s *Service) CreateUser(req CreateUserRequest) (*AuthResponse, error) {
	// Check if user already exists
	_, err := s.repo.GetUserByEmail(req.Email)
	if err == nil {
		return nil, fmt.Errorf("user with email %s already exists", req.Email)
	}

	// Create new user
	user := &User{
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Country:   req.Country,
		Language:  req.Language,
	}

	// Hash password
	if err := user.HashPassword(req.Password); err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Save user
	if err := s.repo.CreateUser(user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Generate tokens
	accessToken, refreshToken, err := s.jwtService.GenerateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &AuthResponse{
		User:         *user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Service) DeleteUser(req DeleteUserRequest) (*AuthResponse, error) {
	// Get user by ID
	user, err := s.repo.GetUserByID(req.ID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Delete user
	if err := s.repo.DeleteUser(user.ID); err != nil {
		return nil, fmt.Errorf("failed to delete user: %w", err)
	}

	return &AuthResponse{
		User:         *user,
		AccessToken:  "",
		RefreshToken: "",
	}, nil
}

func (s *Service) Login(req LoginRequest) (*AuthResponse, error) {
	// Get user by email
	user, err := s.repo.GetUserByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check password
	if !user.CheckPassword(req.Password) {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Generate tokens
	accessToken, refreshToken, err := s.jwtService.GenerateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &AuthResponse{
		User:         *user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Service) UpdateUser(req UpdateUserRequest) (*AuthResponse, error) {
	// Get user by ID
	user, err := s.repo.GetUserByID(req.ID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Update user fields
	user.Email = req.Email
	user.FirstName = req.FirstName
	user.LastName = req.LastName
	user.Country = req.Country
	user.Language = req.Language

	// Save updated user
	if err := s.repo.UpdateUser(user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Generate tokens
	accessToken, refreshToken, err := s.jwtService.GenerateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &AuthResponse{
		User:         *user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Service) ViewUsers() ([]User, error) {
	users, err := s.repo.GetAllUsers()
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	return users, nil
}

func (s *Service) RefreshToken(req RefreshTokenRequest) (*AuthResponse, error) {
	// Validate refresh token
	claims, err := s.jwtService.ValidateToken(req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Get user
	user, err := s.repo.GetUserByID(claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Generate new tokens
	accessToken, refreshToken, err := s.jwtService.GenerateTokens(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &AuthResponse{
		User:         *user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
