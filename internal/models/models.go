package models

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AccessTokenClaims struct {
	UserGUID  string `json:"user_guid"`
	jwt.RegisteredClaims
}

type RefreshToken struct {
	ID            int
	JTI           string
	UserGUID      string
	UserAgentHash string
	TokenHash     string
	IPAddress     string
	ExpiresAt     time.Time
	CreatedAt     time.Time
	IsRevoked     bool
}

type GetTokenRequest struct {
	UserGUID string `json:"user_guid"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

type WebhookPayload struct {
	UserGUID    string    `json:"user_guid"`
	AttemptedIP string    `json:"attempted_ip"`
	OriginalIP  string    `json:"original_ip,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Message     string    `json:"message"`
}

var (
	ErrUserNotFound = errors.New("user not found")
)
