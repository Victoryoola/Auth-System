import { Response } from 'express';
import { DeviceRegistry } from '../services/DeviceRegistry';
import { SessionManager } from '../services/SessionManager';
import { TrustStatus } from '../types/enums';
import { param, body, validationResult } from 'express-validator';
import { AuthenticatedRequest } from '../middleware/accessControl';

/**
 * Device Management Controller
 * Handles device listing, trust status updates, and device revocation
 */
export class DeviceController {
  constructor(
    private deviceRegistry: DeviceRegistry,
    private sessionManager: SessionManager
  ) {}

  /**
   * GET /devices
   * List all devices for the authenticated user
   */
  async listDevices(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.session) {
        res.status(401).json({
          error: 'unauthorized',
          message: 'Authentication required',
        });
        return;
      }

      const { userId } = req.session;

      const devices = await this.deviceRegistry.getUserDevices(userId);

      // Format response
      const formattedDevices = devices.map(device => ({
        id: device.id,
        identity: device.identity,
        trustStatus: device.trustStatus,
        revoked: device.revoked,
        firstSeen: device.firstSeen,
        lastSeen: device.lastSeen,
        deviceType: device.metadata.deviceType,
        browser: device.metadata.browser,
        operatingSystem: device.metadata.operatingSystem,
        lastIpAddress: device.metadata.lastIpAddress,
      }));

      res.status(200).json({
        devices: formattedDevices,
        total: formattedDevices.length,
      });
    } catch (error) {
      this.handleDeviceError(error, res);
    }
  }

  /**
   * PUT /devices/:id/trust
   * Update device trust status
   */
  async updateTrustStatus(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          error: 'validation_error',
          message: 'Invalid input',
          details: errors.array(),
        });
        return;
      }

      if (!req.session) {
        res.status(401).json({
          error: 'unauthorized',
          message: 'Authentication required',
        });
        return;
      }

      const { userId } = req.session;
      const { id: deviceId } = req.params;
      const { trustStatus } = req.body;

      // Get device to verify ownership
      const device = await this.deviceRegistry.getDevice(deviceId);

      if (!device) {
        res.status(404).json({
          error: 'device_not_found',
          message: 'Device not found',
        });
        return;
      }

      // Verify user owns this device
      if (device.userId !== userId) {
        res.status(403).json({
          error: 'forbidden',
          message: 'You do not have permission to modify this device',
        });
        return;
      }

      // Update trust status
      await this.deviceRegistry.updateTrustStatus(deviceId, trustStatus as TrustStatus);

      res.status(200).json({
        message: 'Device trust status updated successfully',
        deviceId,
        trustStatus,
      });
    } catch (error) {
      this.handleDeviceError(error, res);
    }
  }

  /**
   * DELETE /devices/:id
   * Revoke a device and invalidate all its sessions
   */
  async revokeDevice(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          error: 'validation_error',
          message: 'Invalid input',
          details: errors.array(),
        });
        return;
      }

      if (!req.session) {
        res.status(401).json({
          error: 'unauthorized',
          message: 'Authentication required',
        });
        return;
      }

      const { userId } = req.session;
      const { id: deviceId } = req.params;

      // Get device to verify ownership
      const device = await this.deviceRegistry.getDevice(deviceId);

      if (!device) {
        res.status(404).json({
          error: 'device_not_found',
          message: 'Device not found',
        });
        return;
      }

      // Verify user owns this device
      if (device.userId !== userId) {
        res.status(403).json({
          error: 'forbidden',
          message: 'You do not have permission to revoke this device',
        });
        return;
      }

      // Revoke device
      await this.deviceRegistry.revokeDevice(deviceId);

      // Invalidate all sessions from this device
      await this.sessionManager.revokeDeviceSessions(deviceId);

      res.status(200).json({
        message: 'Device revoked successfully',
        deviceId,
      });
    } catch (error) {
      this.handleDeviceError(error, res);
    }
  }

  /**
   * Handle device management errors
   */
  private handleDeviceError(error: unknown, res: Response): void {
    if (error instanceof Error) {
      res.status(500).json({
        error: 'device_operation_failed',
        message: 'Device operation failed',
      });
    } else {
      res.status(500).json({
        error: 'internal_error',
        message: 'An unexpected error occurred',
      });
    }
  }
}

/**
 * Validation rules for device ID parameter
 */
export const deviceIdValidation = [
  param('id').isString().notEmpty().withMessage('Valid device ID is required'),
];

/**
 * Validation rules for trust status update
 */
export const trustStatusValidation = [
  ...deviceIdValidation,
  body('trustStatus')
    .isIn(['TRUSTED', 'UNTRUSTED', 'PENDING'])
    .withMessage('Valid trust status is required (TRUSTED, UNTRUSTED, or PENDING)'),
];
