-- Migration: Create audit_logs table with partitioning
-- Description: Stores security and authentication audit logs

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    user_id UUID NOT NULL,
    session_id UUID,
    device_identity VARCHAR(255),
    ip_address INET,
    success BOOLEAN NOT NULL,
    details JSONB DEFAULT '{}',
    encrypted_fields TEXT[] DEFAULT '{}',
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Create partitions for the current and next 3 months
CREATE TABLE audit_logs_2024_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

CREATE TABLE audit_logs_2024_02 PARTITION OF audit_logs
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');

CREATE TABLE audit_logs_2024_03 PARTITION OF audit_logs
    FOR VALUES FROM ('2024-03-01') TO ('2024-04-01');

CREATE TABLE audit_logs_default PARTITION OF audit_logs DEFAULT;

-- Indexes
CREATE INDEX idx_audit_logs_user_timestamp ON audit_logs(user_id, timestamp DESC);
CREATE INDEX idx_audit_logs_event_timestamp ON audit_logs(event_type, timestamp DESC);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_session ON audit_logs(session_id) WHERE session_id IS NOT NULL;

-- Comments
COMMENT ON TABLE audit_logs IS 'Stores security and authentication audit logs (partitioned by month)';
COMMENT ON COLUMN audit_logs.event_type IS 'Type of event (e.g., LOGIN_ATTEMPT, RISK_EVALUATION, DEVICE_CHANGE)';
COMMENT ON COLUMN audit_logs.success IS 'Whether the event was successful';
COMMENT ON COLUMN audit_logs.details IS 'Additional event details in JSON format';
COMMENT ON COLUMN audit_logs.encrypted_fields IS 'List of field names that are encrypted in details';
