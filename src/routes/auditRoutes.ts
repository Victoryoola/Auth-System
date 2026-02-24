import { Router, Request, Response } from 'express';
import { AuditController, auditLogsValidation } from '../controllers/auditController';
import { AuditLogger } from '../services/AuditLogger';
import { AccessControlMiddleware } from '../middleware/accessControl';

/**
 * Create audit log routes
 */
export function createAuditRoutes(
  auditLogger: AuditLogger,
  accessControl: AccessControlMiddleware
): Router {
  const router = Router();
  const controller = new AuditController(auditLogger);

  /**
   * GET /audit-logs
   * Retrieve audit logs for the authenticated user with optional filters
   * Requires authenticated session (any trust level except HIGH_RISK)
   */
  router.get(
    '/',
    accessControl.requireVerified,
    auditLogsValidation,
    (req: Request, res: Response) => controller.getLogs(req, res)
  );

  return router;
}
