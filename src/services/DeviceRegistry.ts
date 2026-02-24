import crypto from 'crypto';
import { pool } from '../config/database';
import { Device, DeviceMetadata } from '../models/Device';
import { TrustStatus } from '../types/enums';
import { DeviceInfo } from '../types/device';

/**
 * Device Registry Service
 * Manages device identification, registration, and trust status
 */
export class DeviceRegistry {
  /**
   * Generate a unique device identity using SHA-256 hash
   * Combines device characteristics: User-Agent, screen resolution, timezone, language
   * Handles missing or partial device information gracefully
   * 
   * @param deviceInfo - Device characteristics
   * @returns SHA-256 hash of device characteristics
   */
  generateIdentity(deviceInfo: DeviceInfo): string {
    // Extract device characteristics, using empty string for missing values
    const userAgent = deviceInfo.userAgent || '';
    const screenRes = deviceInfo.screenResolution || '';
    const timezone = deviceInfo.timezone || '';
    const language = deviceInfo.language || '';

    // Combine characteristics in a consistent order
    const combined = `${userAgent}|${screenRes}|${timezone}|${language}`;

    // Generate SHA-256 hash
    const hash = crypto.createHash('sha256');
    hash.update(combined);
    
    return hash.digest('hex');
  }

  /**
   * Register a new device or update existing device
   * 
   * @param userId - User ID
   * @param identity - Device identity hash
   * @param metadata - Device metadata
   * @returns Registered device
   */
  async registerDevice(
    userId: string,
    identity: string,
    metadata: DeviceMetadata
  ): Promise<Device> {
    const client = await pool.connect();
    
    try {
      // Check if device already exists for this user
      const existingQuery = `
        SELECT * FROM devices 
        WHERE user_id = $1 AND identity = $2
      `;
      const existingResult = await client.query(existingQuery, [userId, identity]);

      if (existingResult.rows.length > 0) {
        // Update existing device
        const updateQuery = `
          UPDATE devices 
          SET 
            last_seen = CURRENT_TIMESTAMP,
            device_type = $3,
            browser = $4,
            operating_system = $5,
            last_ip_address = $6
          WHERE user_id = $1 AND identity = $2
          RETURNING *
        `;
        
        const result = await client.query(updateQuery, [
          userId,
          identity,
          metadata.deviceType,
          metadata.browser,
          metadata.operatingSystem,
          metadata.lastIpAddress,
        ]);

        return this.mapRowToDevice(result.rows[0]);
      } else {
        // Insert new device
        const insertQuery = `
          INSERT INTO devices (
            user_id, 
            identity, 
            trust_status, 
            device_type, 
            browser, 
            operating_system, 
            last_ip_address
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7)
          RETURNING *
        `;
        
        const result = await client.query(insertQuery, [
          userId,
          identity,
          TrustStatus.UNTRUSTED,
          metadata.deviceType,
          metadata.browser,
          metadata.operatingSystem,
          metadata.lastIpAddress,
        ]);

        return this.mapRowToDevice(result.rows[0]);
      }
    } finally {
      client.release();
    }
  }

  /**
   * Get device by identity
   * 
   * @param identity - Device identity hash
   * @returns Device or null if not found
   */
  async getDevice(identity: string): Promise<Device | null> {
    const query = `
      SELECT * FROM devices 
      WHERE identity = $1
      LIMIT 1
    `;
    
    const result = await pool.query(query, [identity]);
    
    if (result.rows.length === 0) {
      return null;
    }
    
    return this.mapRowToDevice(result.rows[0]);
  }

  /**
   * Get all devices for a user
   * 
   * @param userId - User ID
   * @returns Array of devices
   */
  async getUserDevices(userId: string): Promise<Device[]> {
    const query = `
      SELECT * FROM devices 
      WHERE user_id = $1
      ORDER BY last_seen DESC
    `;
    
    const result = await pool.query(query, [userId]);
    
    return result.rows.map(row => this.mapRowToDevice(row));
  }

  /**
   * Update device trust status
   * 
   * @param identity - Device identity hash
   * @param status - New trust status
   */
  async updateTrustStatus(identity: string, status: TrustStatus): Promise<void> {
    const query = `
      UPDATE devices 
      SET trust_status = $1
      WHERE identity = $2
    `;
    
    await pool.query(query, [status, identity]);
  }

  /**
   * Revoke a device
   * 
   * @param identity - Device identity hash
   */
  async revokeDevice(identity: string): Promise<void> {
    const query = `
      UPDATE devices 
      SET revoked = TRUE, trust_status = $1
      WHERE identity = $2
    `;
    
    await pool.query(query, [TrustStatus.UNTRUSTED, identity]);
  }

  /**
   * Check if a device is trusted for a specific user
   * 
   * @param identity - Device identity hash
   * @param userId - User ID
   * @returns True if device is trusted and not revoked
   */
  async isDeviceTrusted(identity: string, userId: string): Promise<boolean> {
    const query = `
      SELECT trust_status, revoked 
      FROM devices 
      WHERE identity = $1 AND user_id = $2
    `;
    
    const result = await pool.query(query, [identity, userId]);
    
    if (result.rows.length === 0) {
      return false;
    }
    
    const device = result.rows[0];
    return device.trust_status === TrustStatus.TRUSTED && !device.revoked;
  }

  /**
   * Map database row to Device model
   * 
   * @param row - Database row
   * @returns Device object
   */
  private mapRowToDevice(row: any): Device {
    return {
      id: row.id,
      userId: row.user_id,
      identity: row.identity,
      trustStatus: row.trust_status as TrustStatus,
      revoked: row.revoked,
      firstSeen: new Date(row.first_seen),
      lastSeen: new Date(row.last_seen),
      metadata: {
        deviceType: row.device_type,
        browser: row.browser,
        operatingSystem: row.operating_system,
        lastIpAddress: row.last_ip_address,
      },
    };
  }
}
