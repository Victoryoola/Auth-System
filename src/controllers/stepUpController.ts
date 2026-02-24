import { Response } from 'express';
import { StepUpVerifier } from '../services/StepUpVerifier';
import { VerificationMethod } from '../types/enums';
import { body, validationResult } from 'express-validator';
import { AuthenticatedRequest } from '../middleware/accessControl';

/**
 * Step-Up Authentication Controller
 * Handles step-up verification initiation, verification, and OTP resend
 */
export class StepUpController {
  constructor(private stepUpVerifier: StepUpVerifier) {}

  /**
   * POST /auth/step-up/initiate
   * Initiate step-up verification challenge
   */
  async initiate(req: AuthenticatedRequest, res: Response): Promise<void> {
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

      const { method } = req.body;

      // Get user ID and session ID from authenticated request
      if (!req.session) {
        res.status(401).json({
          error: 'unauthorized',
          message: 'Authentication required',
        });
        return;
      }

      const { userId, id: sessionId } = req.session;

      // Initiate verification
      const challenge = await this.stepUpVerifier.initiateVerification(
        userId,
        sessionId,
        method as VerificationMethod
      );

      res.status(200).json({
        challengeId: challenge.id,
        method: challenge.method,
        expiresAt: challenge.expiresAt,
        attemptsRemaining: challenge.attemptsRemaining,
      });
    } catch (error) {
      this.handleStepUpError(error, res);
    }
  }

  /**
   * POST /auth/step-up/verify
   * Verify OTP for step-up authentication
   */
  async verify(req: AuthenticatedRequest, res: Response): Promise<void> {
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

      const { challengeId, otp } = req.body;

      // Verify challenge
      const result = await this.stepUpVerifier.verifyChallenge(challengeId, otp);

      if (!result.success) {
        res.status(401).json({
          error: 'verification_failed',
          message: result.reason || 'Verification failed',
        });
        return;
      }

      res.status(200).json({
        success: true,
        newTrustLevel: result.newTrustLevel,
        message: 'Step-up verification successful',
      });
    } catch (error) {
      this.handleStepUpError(error, res);
    }
  }

  /**
   * POST /auth/step-up/resend
   * Resend OTP for existing challenge
   */
  async resend(req: AuthenticatedRequest, res: Response): Promise<void> {
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

      const { challengeId } = req.body;

      await this.stepUpVerifier.resendChallenge(challengeId);

      res.status(200).json({
        message: 'OTP resent successfully',
      });
    } catch (error) {
      this.handleStepUpError(error, res);
    }
  }

  /**
   * Handle step-up authentication errors
   */
  private handleStepUpError(error: unknown, res: Response): void {
    if (error instanceof Error) {
      const message = error.message;

      if (message === 'Rate limit exceeded. Please try again later.') {
        res.status(429).json({
          error: 'rate_limit_exceeded',
          message: message,
        });
      } else if (message === 'Challenge not found') {
        res.status(404).json({
          error: 'challenge_not_found',
          message: 'The verification challenge was not found',
        });
      } else if (message.includes('expired')) {
        res.status(400).json({
          error: 'challenge_expired',
          message: message,
        });
      } else if (message === 'Challenge already verified') {
        res.status(400).json({
          error: 'already_verified',
          message: 'This challenge has already been verified',
        });
      } else if (message === 'User email not found') {
        res.status(400).json({
          error: 'email_not_found',
          message: 'User email address not found',
        });
      } else if (message === 'User phone number not found') {
        res.status(400).json({
          error: 'phone_not_found',
          message: 'User phone number not found',
        });
      } else if (message === 'Email service not configured') {
        res.status(503).json({
          error: 'service_unavailable',
          message: 'Email service is not available',
        });
      } else if (message === 'SMS service not configured') {
        res.status(503).json({
          error: 'service_unavailable',
          message: 'SMS service is not available',
        });
      } else {
        res.status(500).json({
          error: 'step_up_failed',
          message: 'Step-up verification failed',
        });
      }
    } else {
      res.status(500).json({
        error: 'internal_error',
        message: 'An unexpected error occurred',
      });
    }
  }
}

/**
 * Validation rules for initiate endpoint
 */
export const initiateValidation = [
  body('method')
    .isIn(['EMAIL_OTP', 'SMS_OTP', 'AUTHENTICATOR_APP'])
    .withMessage('Valid verification method is required (EMAIL_OTP, SMS_OTP, or AUTHENTICATOR_APP)'),
];

/**
 * Validation rules for verify endpoint
 */
export const verifyValidation = [
  body('challengeId').isUUID().withMessage('Valid challenge ID is required'),
  body('otp').isString().isLength({ min: 6, max: 6 }).withMessage('Valid 6-digit OTP is required'),
];

/**
 * Validation rules for resend endpoint
 */
export const resendValidation = [
  body('challengeId').isUUID().withMessage('Valid challenge ID is required'),
];
