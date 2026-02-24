import { Router, Request, Response } from 'express';
import { DeviceController, deviceIdValidation, trustStatusValidation } from '../controllers/deviceController';
import { DeviceRegistry } from '../services/DeviceRegistry';
import { SessionManager } from '../services/SessionManager';
import { AccessControlMiddleware } from '../middleware/accessControl';

/**
 * Create device management routes
 */
export function createDeviceRoutes(
  deviceRegistry: DeviceRegistry,
  sessionManager: SessionManager,
  accessControl: AccessControlMiddleware
): Router {
  const router = Router();
  const controller = new DeviceController(deviceRegistry, sessionManager);

  /**
   * GET /devices
   * List all devices for the authenticated user
   * Requires authenticated session (any trust level except HIGH_RISK)
   */
  router.get('/', accessControl.requireVerified, (req: Request, res: Response) => controller.listDevices(req, res));

  /**
   * PUT /devices/:id/trust
   * Update device trust status
   * Requires authenticated session (any trust level except HIGH_RISK)
   */
  router.put(
    '/:id/trust',
    accessControl.requireVerified,
    trustStatusValidation,
    (req: Request, res: Response) => controller.updateTrustStatus(req, res)
  );

  /**
   * DELETE /devices/:id
   * Revoke a device and invalidate all its sessions
   * Requires authenticated session (any trust level except HIGH_RISK)
   */
  router.delete(
    '/:id',
    accessControl.requireVerified,
    deviceIdValidation,
    (req: Request, res: Response) => controller.revokeDevice(req, res)
  );

  return router;
}
