import { Router, Request, Response } from 'express';
import { SessionController, sessionIdValidation } from '../controllers/sessionController';
import { SessionManager } from '../services/SessionManager';
import { AccessControlMiddleware } from '../middleware/accessControl';

/**
 * Create session management routes
 */
export function createSessionRoutes(
  sessionManager: SessionManager,
  accessControl: AccessControlMiddleware
): Router {
  const router = Router();
  const controller = new SessionController(sessionManager);

  /**
   * GET /sessions
   * List all active sessions for the authenticated user
   * Requires authenticated session (any trust level except HIGH_RISK)
   */
  router.get('/', accessControl.requireVerified, (req: Request, res: Response) => controller.listSessions(req, res));

  /**
   * DELETE /sessions/:id
   * Terminate a specific session
   * Requires authenticated session (any trust level except HIGH_RISK)
   */
  router.delete(
    '/:id',
    accessControl.requireVerified,
    sessionIdValidation,
    (req: Request, res: Response) => controller.terminateSession(req, res)
  );

  return router;
}
