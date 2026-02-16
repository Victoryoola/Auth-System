-- Migration: Create risk_evaluations table with partitioning
-- Description: Stores risk assessment results for login attempts

CREATE TABLE IF NOT EXISTS risk_evaluations (
    id UUID DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_identity VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    risk_score INTEGER NOT NULL,
    trust_level VARCHAR(50) NOT NULL,
    device_familiarity INTEGER NOT NULL,
    geographic_anomaly INTEGER NOT NULL,
    ip_reputation INTEGER NOT NULL,
    login_velocity INTEGER NOT NULL,
    failed_attempts INTEGER NOT NULL,
    PRIMARY KEY (id, timestamp),
    CONSTRAINT risk_evaluations_trust_level_check CHECK (trust_level IN ('FULL_TRUST', 'LIMITED_TRUST', 'UNVERIFIED', 'HIGH_RISK')),
    CONSTRAINT risk_evaluations_risk_score_check CHECK (risk_score >= 0 AND risk_score <= 100)
) PARTITION BY RANGE (timestamp);

-- Create partitions for the current and next 3 months
CREATE TABLE risk_evaluations_2024_01 PARTITION OF risk_evaluations
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

CREATE TABLE risk_evaluations_2024_02 PARTITION OF risk_evaluations
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');

CREATE TABLE risk_evaluations_2024_03 PARTITION OF risk_evaluations
    FOR VALUES FROM ('2024-03-01') TO ('2024-04-01');

CREATE TABLE risk_evaluations_default PARTITION OF risk_evaluations DEFAULT;

-- Indexes
CREATE INDEX idx_risk_evaluations_user_timestamp ON risk_evaluations(user_id, timestamp DESC);
CREATE INDEX idx_risk_evaluations_timestamp ON risk_evaluations(timestamp DESC);
CREATE INDEX idx_risk_evaluations_device ON risk_evaluations(device_identity);

-- Comments
COMMENT ON TABLE risk_evaluations IS 'Stores risk assessment results for login attempts (partitioned by month)';
COMMENT ON COLUMN risk_evaluations.risk_score IS 'Overall risk score (0-100)';
COMMENT ON COLUMN risk_evaluations.trust_level IS 'Assigned trust level based on risk score';
COMMENT ON COLUMN risk_evaluations.device_familiarity IS 'Device familiarity factor contribution';
COMMENT ON COLUMN risk_evaluations.geographic_anomaly IS 'Geographic anomaly factor contribution';
COMMENT ON COLUMN risk_evaluations.ip_reputation IS 'IP reputation factor contribution';
COMMENT ON COLUMN risk_evaluations.login_velocity IS 'Login velocity factor contribution';
COMMENT ON COLUMN risk_evaluations.failed_attempts IS 'Failed attempts factor contribution';
