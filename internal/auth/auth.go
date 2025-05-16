package auth

import (
	"TestTaskAuthorization/internal/models"
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	RefreshTokenSecretLength = 32
)

type Auth interface {
	GenerateAccessToken(userID, clientIP, jti string) (string, error)
	GenerateRefreshToken() (string, string, error)
	HashRefreshToken(refreshToken string) (string, error)
	ParseAccessToken(accessToken string) (models.AccessTokenClaims, error)
}

type auth struct {
	jwtSecret       []byte
	accessDuration  time.Duration
	refreshDuration time.Duration
	logger          *slog.Logger
}

func NewAuth(secret string, accessDur, refreshDur time.Duration, logger *slog.Logger) Auth {
	return &auth{
		jwtSecret:       []byte(secret),
		accessDuration:  accessDur,
		refreshDuration: refreshDur,
		logger:          logger,
	}
}

func (a *auth) GenerateAccessToken(UserGUID, clientIP, jti string) (string, error) {
	claims := models.AccessTokenClaims{
		UserGUID: UserGUID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(a.accessDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedToken, err := token.SignedString(a.jwtSecret)
	if err != nil {
		a.logger.Error("failed to sign access token", "error", err)
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return signedToken, nil
}

func (a *auth) GenerateRefreshToken() (string, string, error) {
	jti := uuid.NewString()

	secretBytes := make([]byte, RefreshTokenSecretLength)
	_, err := rand.Read(secretBytes)
	if err != nil {
		a.logger.Error("failed to generate refresh token secret", "error", err)
		return "", "", fmt.Errorf("failed to generate refresh token secret: %w", err)

	}

	refreshToken := fmt.Sprintf("%s.%s", jti, secretBytes)

	return jti, refreshToken, nil

}

func (a *auth) HashRefreshToken(refreshToken string) (string, error) {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedToken), nil
}

func (a *auth) ParseAccessToken(accessToken string) (models.AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(accessToken, &models.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(a.jwtSecret), nil
	})
	if err != nil {
		a.logger.Error("failed to parse access token", "error", err)
		return models.AccessTokenClaims{}, err
	}


	claims, ok := token.Claims.(*models.AccessTokenClaims)
	if !ok || !token.Valid {
		err := fmt.Errorf("invalid access token")
		a.logger.Error("invalid access token", "error", err)
		return models.AccessTokenClaims{}, err
	}
	

	return *claims, nil
}
