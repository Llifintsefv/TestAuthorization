CREATE TABLE IF NOT EXISTS refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_GUID UUID NOT NULL, 
    jti VARCHAR(255) NOT NULL UNIQUE,
    user_agent_hash VARCHAR(64),
    token_hash VARCHAR(255) NOT NULL UNIQUE, 
    ip_address VARCHAR(45),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_guid ON refresh_tokens(user_GUID);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);