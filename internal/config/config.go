package config

import (
	"fmt"
	"log/slog"
	"os"
	"time"
)

type Config struct {
	DBConnStr            string
	Port                 string
	SecretKey            string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	WebhookURL           string
}

func NewConfig() (*Config, error) {
	// err := godotenv.Load(".env")
	// if err != nil {
	// 	slog.Error("DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, DB_SSL_MODE must be set")
	// 	return nil, fmt.Errorf("missing required environment variables")
	// }
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbSSLMode := os.Getenv("DB_SSL_MODE")

	if dbHost == "" || dbPort == "" || dbUser == "" || dbPassword == "" || dbName == "" || dbSSLMode == "" {
		slog.Error("DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, DB_SSL_MODE must be set")
		return nil, fmt.Errorf("missing required environment variables")
	}

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", dbUser, dbPassword, dbHost, dbPort, dbName, dbSSLMode)

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = ":8080"
	}

	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		slog.Error("SECRET_KEY must be set")
		return nil, fmt.Errorf("missing required environment variables")
	}

	accessDurStr := os.Getenv("ACCESS_TOKEN_TTL")
	if accessDurStr == "" {
		accessDurStr = "15m"
	}
	accessTokenDuration, err := time.ParseDuration(accessDurStr)
	if err != nil {
		slog.Warn("Invalid ACCESS_TOKEN_TTL, using default 15m", "error", err)
		accessTokenDuration = 15 * time.Minute
	}

	refreshDurStr := os.Getenv("REFRESH_TOKEN_TTL")
	if refreshDurStr == "" {
		refreshDurStr = "72h"
	}
	refreshTokenDuration, err := time.ParseDuration(refreshDurStr)
	if err != nil {
		slog.Warn("Invalid REFRESH_TOKEN_TTL, using default 72h", "error", err)
		refreshTokenDuration = 72 * time.Hour
	}

	webhookURL := os.Getenv("WEBHOOK_URL")
	if webhookURL == "" {
		slog.Error("WEBHOOK_URL must be set")
		return nil, fmt.Errorf("missing required environment variables")
	}

	return &Config{
		DBConnStr:            connStr,
		Port:                 port,
		SecretKey:            secretKey,
		AccessTokenDuration:  accessTokenDuration,
		RefreshTokenDuration: refreshTokenDuration,
		WebhookURL:           webhookURL,
	}, nil
}
