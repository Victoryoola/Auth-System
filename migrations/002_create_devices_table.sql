-- Migration: Create devices table
-- Description: Stores device recognition data and trust status

CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identity VARCHAR(255) NOT NULL,
    trust_status VARCHAR(50) NOT NULL DEFAULT 'UNTRUSTED',
    revoked BOOLEAN DEFAULT FALSE,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    device_type VARCHAR(100),
    browser VARCHAR(100),
    operating_system VARCHAR(100),
    last_ip_address INET,
    CONSTRAINT devices_trust_status_check CHECK (trust_status IN ('TRUSTED', 'UNTRUSTED', 'PENDING'))
);

-- Indexes
CREATE INDEX idx_devices_user_id ON devices(user_id);
CREATE INDEX idx_devices_identity ON devices(identity);
CREATE INDEX idx_devices_user_identity ON devices(user_id, identity);
CREATE INDEX idx_devices_trust_status ON devices(trust_status);
CREATE INDEX idx_devices_revoked ON devices(revoked);

-- Comments
COMMENT ON TABLE devices IS 'Stores device recognition data and trust status';
COMMENT ON COLUMN devices.identity IS 'SHA-256 hash of device characteristics';
COMMENT ON COLUMN devices.trust_status IS 'Trust level: TRUSTED, UNTRUSTED, or PENDING';
COMMENT ON COLUMN devices.revoked IS 'Whether the device has been revoked by the user';
COMMENT ON COLUMN devices.device_type IS 'Device type (mobile, desktop, tablet)';
COMMENT ON COLUMN devices.browser IS 'Browser name and version';
COMMENT ON COLUMN devices.operating_system IS 'Operating system name and version';
