-- Migration: Add device tracking preference to users table
-- Task: 13. Implement privacy and user control features

-- Add device_tracking_enabled column to users table
ALTER TABLE users 
ADD COLUMN device_tracking_enabled BOOLEAN NOT NULL DEFAULT TRUE;

-- Add comment for documentation
COMMENT ON COLUMN users.device_tracking_enabled IS 'User preference for device tracking. When false, device identification is disabled while maintaining security controls.';
