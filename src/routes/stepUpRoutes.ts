import { Router, Request, Response } from 'express';
import { StepUpController, initiateValidation, verifyValidation, resendValidation } from '../controllers/stepUpController';
import { StepUpVerifier } from '../services/StepUpVerifier';
import { AccessControlMiddleware } from '../middleware/accessControl';

/**
 * Create step-up authentication routes
 */
export function createStepUpRoutes(
  stepUpVerifier: StepUpVerifier,
  accessControl: AccessControlMiddleware
): Router {
  const router = Router();
  const controller = new StepUpController(stepUpVerifier);

  /**
   * POST /auth/step-up/initiate
   * Initiate step-up verification challenge
   * Requires authenticated session (any trust level except HIGH_RISK)
   */
  router.post(
    '/initiate',
    accessControl.requireVerified,
    initiateValidation,
    (req: Request, res: Response) => controller.initiate(req, res)
  );

  /**
   * POST /auth/step-up/verify
   * Verify OTP for step-up authentication
   * No authentication required (challenge ID is sufficient)
   */
  router.post('/verify', verifyValidation, (req: Request, res: Response) => controller.verify(req, res));

  /**
   * POST /auth/step-up/resend
   * Resend OTP for existing challenge
   * No authentication required (challenge ID is sufficient)
   */
  router.post('/resend', resendValidation, (req: Request, res: Response) => controller.resend(req, res));

  return router;
}
