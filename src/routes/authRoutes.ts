import { Router } from 'express';
import { AuthController, loginValidation, mfaVerifyValidation, logoutValidation, refreshValidation } from '../controllers/authController';
import { AuthService } from '../services/AuthService';
import { SessionManager } from '../services/SessionManager';
import { DeviceRegistry } from '../services/DeviceRegistry';
import { RiskEngine } from '../services/RiskEngine';

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
  router.post('/login', loginValidation, (req, res) => controller.login(req, res));

  /**
   * POST /auth/mfa/verify
   * Verify MFA code after initial authentication
   */
  router.post('/mfa/verify', mfaVerifyValidation, (req, res) => controller.verifyMFA(req, res));

  /**
   * POST /auth/logout
   * Terminate user session
   */
  router.post('/logout', logoutValidation, (req, res) => controller.logout(req, res));

  /**
   * POST /auth/refresh
   * Refresh access token using refresh token
   */
  router.post('/refresh', refreshValidation, (req, res) => controller.refresh(req, res));

  return router;
}
