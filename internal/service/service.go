package service

import (
	"TestTaskAuthorization/internal/auth"
	"TestTaskAuthorization/internal/config"
	"TestTaskAuthorization/internal/models"
	"TestTaskAuthorization/internal/repository"
	"TestTaskAuthorization/internal/utils"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Service interface {
	GetTokenPair(ctx context.Context, userID string, clientIP string, userAgent string) (models.TokenPair, error)
	RefreshToken(ctx context.Context, refreshToken string, clientIP string, userAgent string) (models.TokenPair, error)
	UserLogout(ctx context.Context, refreshToken string) error
}

type service struct {
	repo   repository.Repository
	auth   auth.Auth
	cfg    config.Config
	logger *slog.Logger
}

func NewService(repo repository.Repository, auth auth.Auth, cfg config.Config, logger *slog.Logger) Service {
	return &service{
		repo:   repo,
		auth:   auth,
		cfg:    cfg,
		logger: logger,
	}
}

func (s *service) GetTokenPair(ctx context.Context, userGUID string, clientIP string, userAgent string) (models.TokenPair, error) {
	jti, refreshToken, err := s.auth.GenerateRefreshToken()
	if err != nil {
		return models.TokenPair{}, err
	}

	accessToken, err := s.auth.GenerateAccessToken(userGUID, clientIP, jti)
	if err != nil {
		return models.TokenPair{}, err
	}

	refreshTokenHash, err := s.auth.HashRefreshToken(refreshToken)
	if err != nil {
		return models.TokenPair{}, err
	}

	userAgentHash := utils.HashStringSHA256(userAgent)

	refreshTokenData := models.RefreshToken{
		UserGUID:      userGUID,
		TokenHash:     refreshTokenHash,
		UserAgentHash: userAgentHash,
		JTI:           jti,
		IPAddress:     clientIP,
		ExpiresAt:     time.Now().Add(s.cfg.RefreshTokenDuration),
	}

	err = s.repo.SaveRefresh(ctx, refreshTokenData)
	if err != nil {
		return models.TokenPair{}, err
	}

	refreshToken = base64.StdEncoding.EncodeToString([]byte(refreshToken))

	return models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil

}

func (s *service) RefreshToken(ctx context.Context, refreshToken string, clientIP string, userAgent string) (models.TokenPair, error) {

	rawRefreshTokenBytes, err := base64.StdEncoding.DecodeString(refreshToken)
	if err != nil {
		s.logger.WarnContext(ctx, "failed to decode base64 refresh token", slog.Any("error", err))
		return models.TokenPair{}, errors.New("invalid refresh token format")
	}
	RawRefreshToken := string(rawRefreshTokenBytes)

	parts := strings.SplitN(RawRefreshToken, ".", 2)

	jti := parts[0]

	TokenData, err := s.repo.GetRefreshToken(ctx, jti)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return models.TokenPair{}, errors.New("refresh token not found")
		}
		return models.TokenPair{}, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(TokenData.TokenHash), []byte(RawRefreshToken)); err != nil {
		s.logger.InfoContext(ctx, "Refresh token changed", "user_id", TokenData.UserGUID)
		err = s.repo.RevokeAllUserTokens(ctx, TokenData.UserGUID)
		if err != nil {
			return models.TokenPair{}, err
		}
		return models.TokenPair{}, errors.New("refresh token changed")
	}

	if TokenData.UserAgentHash != utils.HashStringSHA256(userAgent) {
		s.logger.InfoContext(ctx, "User agent changed", "user_id", TokenData.UserGUID, "old_user_agent", TokenData.UserAgentHash, "new_user_agent", userAgent)
		err = s.repo.RevokeAllUserTokens(ctx, TokenData.UserGUID)
		if err != nil {
			return models.TokenPair{}, err
		}
		return models.TokenPair{}, errors.New("user agent changed")
	}

	if TokenData.IPAddress != clientIP {
		s.logger.InfoContext(ctx, "IP address changed", "user_id", TokenData.UserGUID, "old_ip", TokenData.IPAddress, "new_ip", clientIP)
		s.sendIPChangeNotification(ctx, TokenData.UserGUID, clientIP, TokenData.IPAddress)
	}

	err = s.repo.RevokeUserToken(ctx, TokenData.TokenHash)
	if err != nil {
		return models.TokenPair{}, err
	}

	newTokenPair, err := s.GetTokenPair(ctx, TokenData.UserGUID, clientIP, userAgent)
	if err != nil {
		return models.TokenPair{}, err
	}

	return newTokenPair, nil

}

func (s *service) sendIPChangeNotification(ctx context.Context, userID, newIP, oldIP string) {
	if s.cfg.WebhookURL == "" {
		s.logger.InfoContext(ctx, "Webhook URL not configured, skipping IP change notification", "user_id", userID)
		return
	}

	payload := models.WebhookPayload{
		UserGUID:    userID,
		AttemptedIP: newIP,
		OriginalIP:  oldIP,
		Timestamp:   time.Now().UTC(),
		Message:     "Refresh token attempt from a new IP address.",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to marshal webhook payload", "error", err, "user_id", userID)
		return
	}

	requestContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(requestContext, "POST", s.cfg.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		s.logger.ErrorContext(requestContext, "Failed to create webhook request", "error", err, "user_id", userID, "webhook_url", s.cfg.WebhookURL)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		s.logger.ErrorContext(requestContext, "Failed to send webhook notification", "error", err, "user_id", userID, "webhook_url", s.cfg.WebhookURL)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		s.logger.InfoContext(requestContext, "Successfully sent IP change notification to webhook", "user_id", userID, "status_code", resp.StatusCode)
	} else {
		s.logger.ErrorContext(requestContext, "Webhook notification request failed", "user_id", userID, "status_code", resp.StatusCode, "webhook_url", s.cfg.WebhookURL)
	}
}

func (s *service) UserLogout(ctx context.Context, userGUID string) error {
	return s.repo.RevokeAllUserTokens(ctx, userGUID)
}
