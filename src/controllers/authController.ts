import { Request, Response } from 'express';
import { AuthService } from '../services/AuthService';
import { SessionManager } from '../services/SessionManager';
import { DeviceInfo } from '../types/device';
import { body, validationResult } from 'express-validator';

/**
 * Authentication Controller
 * Handles user authentication, logout, token refresh, and MFA verification
 */
export class AuthController {
  constructor(
    private authService: AuthService,
    private sessionManager: SessionManager
  ) {}

  /**
   * POST /auth/login
   * Authenticate user with email and password
   */
  async login(req: Request, res: Response): Promise<void> {
    try {
      // Validate input
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          error: 'validation_error',
          message: 'Invalid input',
          details: errors.array(),
        });
        return;
      }

      const { email, password, deviceInfo } = req.body;

      // Extract device information
      const device: DeviceInfo = {
        userAgent: deviceInfo?.userAgent || req.headers['user-agent'] || '',
        ipAddress: deviceInfo?.ipAddress || req.ip || '',
        screenResolution: deviceInfo?.screenResolution,
        timezone: deviceInfo?.timezone,
        language: deviceInfo?.language,
      };

      // Authenticate
      const result = await this.authService.authenticate(
        { email, password },
        device
      );

      // If MFA is required, return partial response
      if (result.requiresMFA) {
        res.status(200).json({
          requiresMFA: true,
          userId: result.userId,
          message: 'MFA verification required',
        });
        return;
      }

      // Return tokens and trust level
      res.status(200).json({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        trustLevel: result.trustLevel,
        expiresIn: result.expiresIn,
      });
    } catch (error) {
      this.handleAuthError(error, res);
    }
  }

  /**
   * POST /auth/mfa/verify
   * Verify MFA code after initial authentication
   */
  async verifyMFA(req: Request, res: Response): Promise<void> {
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

      const { userId, mfaCode, deviceInfo } = req.body;

      // Extract device information
      const device: DeviceInfo = {
        userAgent: deviceInfo?.userAgent || req.headers['user-agent'] || '',
        ipAddress: deviceInfo?.ipAddress || req.ip || '',
        screenResolution: deviceInfo?.screenResolution,
        timezone: deviceInfo?.timezone,
        language: deviceInfo?.language,
      };

      // Verify MFA
      const result = await this.authService.verifyMFA(userId, mfaCode, device);

      res.status(200).json({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        trustLevel: result.trustLevel,
        expiresIn: result.expiresIn,
      });
    } catch (error) {
      this.handleAuthError(error, res);
    }
  }

  /**
   * POST /auth/logout
   * Terminate user session
   */
  async logout(req: Request, res: Response): Promise<void> {
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

      const { sessionId } = req.body;

      await this.authService.logout(sessionId);

      res.status(200).json({
        message: 'Logout successful',
      });
    } catch (error) {
      if (error instanceof Error) {
        res.status(500).json({
          error: 'logout_failed',
          message: error.message,
        });
      } else {
        res.status(500).json({
          error: 'logout_failed',
          message: 'An unexpected error occurred',
        });
      }
    }
  }

  /**
   * POST /auth/refresh
   * Refresh access token using refresh token
   */
  async refresh(req: Request, res: Response): Promise<void> {
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

      const { refreshToken } = req.body;

      const result = await this.sessionManager.refreshSession(refreshToken);

      res.status(200).json({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        expiresIn: result.expiresIn,
      });
    } catch (error) {
      if (error instanceof Error) {
        if (error.message.includes('replay attack')) {
          res.status(401).json({
            error: 'token_replay_detected',
            message: 'Potential security threat detected. All sessions have been revoked.',
          });
        } else if (error.message.includes('expired')) {
          res.status(401).json({
            error: 'token_expired',
            message: 'Refresh token has expired. Please login again.',
          });
        } else {
          res.status(401).json({
            error: 'invalid_token',
            message: 'Invalid refresh token',
          });
        }
      } else {
        res.status(500).json({
          error: 'refresh_failed',
          message: 'An unexpected error occurred',
        });
      }
    }
  }

  /**
   * Handle authentication errors with appropriate HTTP status codes
   */
  private handleAuthError(error: unknown, res: Response): void {
    if (error instanceof Error) {
      const message = error.message;

      if (message === 'Invalid credentials') {
        res.status(401).json({
          error: 'invalid_credentials',
          message: 'Invalid email or password',
        });
      } else if (message.includes('Account locked')) {
        res.status(403).json({
          error: 'account_locked',
          message: message,
        });
      } else if (message === 'CAPTCHA verification required') {
        res.status(429).json({
          error: 'captcha_required',
          message: 'CAPTCHA verification required due to multiple failed attempts',
        });
      } else if (message === 'Rate limit exceeded. Please try again later.') {
        res.status(429).json({
          error: 'rate_limit_exceeded',
          message: message,
        });
      } else if (message === 'Invalid MFA code') {
        res.status(401).json({
          error: 'invalid_mfa_code',
          message: 'The MFA code provided is invalid',
        });
      } else if (message === 'User not found') {
        res.status(401).json({
          error: 'invalid_credentials',
          message: 'Invalid email or password',
        });
      } else if (message === 'MFA not enabled for this user') {
        res.status(400).json({
          error: 'mfa_not_enabled',
          message: 'MFA is not enabled for this account',
        });
      } else {
        res.status(500).json({
          error: 'authentication_failed',
          message: 'Authentication failed',
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
 * Validation rules for login endpoint
 */
export const loginValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password').isString().notEmpty().withMessage('Password is required'),
  body('deviceInfo').optional().isObject(),
  body('deviceInfo.userAgent').optional().isString(),
  body('deviceInfo.ipAddress').optional().isString(),
  body('deviceInfo.screenResolution').optional().isString(),
  body('deviceInfo.timezone').optional().isString(),
  body('deviceInfo.language').optional().isString(),
];

/**
 * Validation rules for MFA verification endpoint
 */
export const mfaVerifyValidation = [
  body('userId').isUUID().withMessage('Valid user ID is required'),
  body('mfaCode').isString().isLength({ min: 6, max: 6 }).withMessage('Valid 6-digit MFA code is required'),
  body('deviceInfo').optional().isObject(),
];

/**
 * Validation rules for logout endpoint
 */
export const logoutValidation = [
  body('sessionId').isUUID().withMessage('Valid session ID is required'),
];

/**
 * Validation rules for refresh endpoint
 */
export const refreshValidation = [
  body('refreshToken').isString().notEmpty().withMessage('Refresh token is required'),
];
