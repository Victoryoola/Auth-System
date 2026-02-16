-- Migration: Create challenges table
-- Description: Stores step-up authentication challenges

CREATE TABLE IF NOT EXISTS challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    method VARCHAR(50) NOT NULL,
    otp_hash VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    attempts_remaining INTEGER DEFAULT 3,
    verified BOOLEAN DEFAULT FALSE,
    CONSTRAINT challenges_method_check CHECK (method IN ('EMAIL_OTP', 'SMS_OTP', 'AUTHENTICATOR_APP')),
    CONSTRAINT challenges_attempts_check CHECK (attempts_remaining >= 0)
);

-- Indexes
CREATE INDEX idx_challenges_user_id ON challenges(user_id);
CREATE INDEX idx_challenges_session_id ON challenges(session_id);
CREATE INDEX idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX idx_challenges_verified ON challenges(verified);

-- Comments
COMMENT ON TABLE challenges IS 'Stores step-up authentication challenges';
COMMENT ON COLUMN challenges.method IS 'Verification method: EMAIL_OTP, SMS_OTP, or AUTHENTICATOR_APP';
COMMENT ON COLUMN challenges.otp_hash IS 'Hash of the OTP (not stored in plaintext)';
COMMENT ON COLUMN challenges.attempts_remaining IS 'Number of verification attempts remaining';
COMMENT ON COLUMN challenges.verified IS 'Whether the challenge was successfully verified';
