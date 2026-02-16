-- Migration: Create sessions table
-- Description: Stores active user sessions with trust levels

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    trust_level VARCHAR(50) NOT NULL,
    device_identity VARCHAR(255) NOT NULL,
    access_token_hash VARCHAR(255) NOT NULL,
    refresh_token_hash VARCHAR(255) NOT NULL,
    refresh_token_family VARCHAR(255) NOT NULL,
    access_token_expiry TIMESTAMP WITH TIME ZONE NOT NULL,
    refresh_token_expiry TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ip_address INET NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    CONSTRAINT sessions_trust_level_check CHECK (trust_level IN ('FULL_TRUST', 'LIMITED_TRUST', 'UNVERIFIED', 'HIGH_RISK'))
);

-- Indexes
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_refresh_token_hash ON sessions(refresh_token_hash);
CREATE INDEX idx_sessions_device_identity ON sessions(device_identity);
CREATE INDEX idx_sessions_revoked ON sessions(revoked);
CREATE INDEX idx_sessions_expiry ON sessions(refresh_token_expiry);
CREATE INDEX idx_sessions_user_active ON sessions(user_id, revoked) WHERE revoked = FALSE;

-- Comments
COMMENT ON TABLE sessions IS 'Stores active user sessions with trust levels';
COMMENT ON COLUMN sessions.trust_level IS 'Session trust level: FULL_TRUST, LIMITED_TRUST, UNVERIFIED, HIGH_RISK';
COMMENT ON COLUMN sessions.device_identity IS 'Device identity hash for this session';
COMMENT ON COLUMN sessions.access_token_hash IS 'Hash of the access token';
COMMENT ON COLUMN sessions.refresh_token_hash IS 'Hash of the refresh token';
COMMENT ON COLUMN sessions.refresh_token_family IS 'Token family for replay detection';
COMMENT ON COLUMN sessions.revoked IS 'Whether the session has been revoked';
