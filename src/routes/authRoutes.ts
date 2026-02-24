import { Router, Request, Response } from 'express';
import { AuthController, loginValidation, mfaVerifyValidation, logoutValidation, refreshValidation } from '../controllers/authController';
import { AuthService } from '../services/AuthService';
import { SessionManager } from '../services/SessionManager';

/**
 * Create authentication routes
 */
export function createAuthRoutes(
  authService: AuthService,
  sessionManager: SessionManager
): Router {
  const router = Router();
  const controller = new AuthController(authService, sessionManager);

  /**
   * POST /auth/login
   * User authentication with email and password
   */
  router.post('/login', loginValidation, (req: Request, res: Response) => controller.login(req, res));

  /**
   * POST /auth/mfa/verify
   * Verify MFA code after initial authentication
   */
  router.post('/mfa/verify', mfaVerifyValidation, (req: Request, res: Response) => controller.verifyMFA(req, res));

  /**
   * POST /auth/logout
   * Terminate user session
   */
  router.post('/logout', logoutValidation, (req: Request, res: Response) => controller.logout(req, res));

  /**
   * POST /auth/refresh
   * Refresh access token using refresh token
   */
  router.post('/refresh', refreshValidation, (req: Request, res: Response) => controller.refresh(req, res));

  return router;
}
