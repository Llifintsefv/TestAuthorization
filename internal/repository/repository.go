package repository

import (
	"TestTaskAuthorization/internal/models"
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository interface {
	SaveRefresh(ctx context.Context, refreshTokenData models.RefreshToken) error
	GetRefreshToken(ctx context.Context, refreshTokenHash string) (models.RefreshToken, error)
	RevokeAllUserTokens(ctx context.Context, userGUID string) error
	RevokeUserToken(ctx context.Context, refreshTokenHash string) error
}

type repository struct {
	db     *pgxpool.Pool
	logger *slog.Logger
}

func NewRepository(db *pgxpool.Pool, logger *slog.Logger) Repository {
	return &repository{
		db:     db,
		logger: logger,
	}
}
func NewDB(strConn string) (*pgxpool.Pool, error) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, strConn)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return pool, nil
}

func (r *repository) SaveRefresh(ctx context.Context, refreshTokenData models.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (jti, token_hash, user_GUID, expires_at, ip_address, user_agent_hash) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := r.db.Exec(ctx, query, refreshTokenData.JTI, refreshTokenData.TokenHash, refreshTokenData.UserGUID, refreshTokenData.ExpiresAt, refreshTokenData.IPAddress, refreshTokenData.UserAgentHash)
	if err != nil {
		r.logger.Error("failed to save refresh token", "error", err)
		return err
	}
	return nil
}

func (r *repository) GetRefreshToken(ctx context.Context, jti string) (models.RefreshToken, error) {
	query := `SELECT token_hash, user_GUID, expires_at, ip_address, user_agent_hash FROM refresh_tokens WHERE jti = $1 AND is_revoked = FALSE`
	rows, err := r.db.Query(ctx, query, jti)
	if err != nil {
		r.logger.Error("failed to get refresh token", "error", err)
		return models.RefreshToken{}, err
	}
	defer rows.Close()
	var refreshTokenData models.RefreshToken
	if rows.Next() {
		if err := rows.Scan(&refreshTokenData.TokenHash, &refreshTokenData.UserGUID, &refreshTokenData.ExpiresAt, &refreshTokenData.IPAddress, &refreshTokenData.UserAgentHash); err != nil {
			r.logger.Error("failed to scan refresh token", "error", err)
			return models.RefreshToken{}, err
		}
		return refreshTokenData, nil
	}
	return models.RefreshToken{}, models.ErrUserNotFound
}

func (r *repository) RevokeAllUserTokens(ctx context.Context, userGUID string) error {
	query := `UPDATE refresh_tokens SET is_revoked = TRUE WHERE user_GUID = $1`
	_, err := r.db.Exec(ctx, query, userGUID)
	if err != nil {
		r.logger.Error("failed to revoke all user tokens", "error", err)
		return err
	}
	return nil
}

func (r *repository) RevokeUserToken(ctx context.Context, refreshTokenHash string) error {
	query := `UPDATE refresh_tokens SET is_revoked = TRUE WHERE token_hash = $1`
	_, err := r.db.Exec(ctx, query, refreshTokenHash)
	if err != nil {
		r.logger.Error("failed to revoke user token", "error", err)
		return err
	}
	return nil
}
