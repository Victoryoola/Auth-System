import { Request, Response, NextFunction } from 'express';
import { SessionManager } from '../services/SessionManager';
import { SessionTrustLevel } from '../types/enums';

/**
 * Extended Express Request with session information
 */
export interface AuthenticatedRequest extends Request {
  session?: {
    id: string;
    userId: string;
    trustLevel: SessionTrustLevel;
    deviceIdentity: string;
  };
}

/**
 * Middleware factory for session access control
 */
export class AccessControlMiddleware {
  constructor(private sessionManager: SessionManager) {}

  /**
   * Extract and validate access token from Authorization header
   */
  private async extractAndValidateToken(req: Request): Promise<{
    valid: boolean;
    session?: any;
    reason?: string;
  }> {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        valid: false,
        reason: 'Missing or invalid Authorization header',
      };
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix
    return await this.sessionManager.validateToken(token);
  }

  /**
   * Middleware to require FULL_TRUST level
   * Allows only sessions with FULL_TRUST
   */
  requireFullTrust = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const validation = await this.extractAndValidateToken(req);

      if (!validation.valid || !validation.session) {
        res.status(401).json({
          error: 'Unauthorized',
          message: validation.reason || 'Invalid or expired token',
        });
        return;
      }

      const { session } = validation;

      // Check if trust level is FULL_TRUST
      if (session.trustLevel !== SessionTrustLevel.FULL_TRUST) {
        res.status(403).json({
          error: 'Forbidden',
          message: 'This operation requires full trust level',
          currentTrustLevel: session.trustLevel,
          requiredTrustLevel: SessionTrustLevel.FULL_TRUST,
          hint: 'Complete step-up authentication to gain full trust',
        });
        return;
      }

      // Attach session info to request
      req.session = {
        id: session.id,
        userId: session.userId,
        trustLevel: session.trustLevel,
        deviceIdentity: session.deviceIdentity,
      };

      next();
    } catch (error) {
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to validate session',
      });
    }
  };

  /**
   * Middleware to require at least LIMITED_TRUST level
   * Allows sessions with FULL_TRUST or LIMITED_TRUST
   * Blocks UNVERIFIED and HIGH_RISK
   */
  requireLimitedTrust = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const validation = await this.extractAndValidateToken(req);

      if (!validation.valid || !validation.session) {
        res.status(401).json({
          error: 'Unauthorized',
          message: validation.reason || 'Invalid or expired token',
        });
        return;
      }

      const { session } = validation;

      // Check if trust level is at least LIMITED_TRUST
      const allowedLevels = [SessionTrustLevel.FULL_TRUST, SessionTrustLevel.LIMITED_TRUST];

      if (!allowedLevels.includes(session.trustLevel)) {
        res.status(403).json({
          error: 'Forbidden',
          message: 'This operation requires at least limited trust level',
          currentTrustLevel: session.trustLevel,
          requiredTrustLevel: 'LIMITED_TRUST or higher',
          hint:
            session.trustLevel === SessionTrustLevel.UNVERIFIED
              ? 'Complete step-up authentication to gain access'
              : 'Your session has been flagged as high risk',
        });
        return;
      }

      // Attach session info to request
      req.session = {
        id: session.id,
        userId: session.userId,
        trustLevel: session.trustLevel,
        deviceIdentity: session.deviceIdentity,
      };

      next();
    } catch (error) {
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to validate session',
      });
    }
  };

  /**
   * Middleware to require at least UNVERIFIED level (any authenticated session except HIGH_RISK)
   * Allows sessions with FULL_TRUST, LIMITED_TRUST, or UNVERIFIED
   * Blocks only HIGH_RISK
   */
  requireVerified = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const validation = await this.extractAndValidateToken(req);

      if (!validation.valid || !validation.session) {
        res.status(401).json({
          error: 'Unauthorized',
          message: validation.reason || 'Invalid or expired token',
        });
        return;
      }

      const { session } = validation;

      // Block only HIGH_RISK sessions
      if (session.trustLevel === SessionTrustLevel.HIGH_RISK) {
        res.status(403).json({
          error: 'Forbidden',
          message: 'Access denied due to high risk assessment',
          currentTrustLevel: session.trustLevel,
          hint: 'Your session has been flagged as high risk. Please contact support.',
        });
        return;
      }

      // Attach session info to request
      req.session = {
        id: session.id,
        userId: session.userId,
        trustLevel: session.trustLevel,
        deviceIdentity: session.deviceIdentity,
      };

      next();
    } catch (error) {
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to validate session',
      });
    }
  };

  /**
   * Middleware to check if operation is sensitive and enforce appropriate restrictions
   * This is a helper that can be combined with other middleware
   */
  restrictSensitiveOperation = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const validation = await this.extractAndValidateToken(req);

      if (!validation.valid || !validation.session) {
        res.status(401).json({
          error: 'Unauthorized',
          message: validation.reason || 'Invalid or expired token',
        });
        return;
      }

      const { session } = validation;

      // Attach session info to request
      req.session = {
        id: session.id,
        userId: session.userId,
        trustLevel: session.trustLevel,
        deviceIdentity: session.deviceIdentity,
      };

      // LIMITED_TRUST: Restrict sensitive operations
      if (session.trustLevel === SessionTrustLevel.LIMITED_TRUST) {
        res.status(403).json({
          error: 'Forbidden',
          message: 'Sensitive operations are restricted for limited trust sessions',
          currentTrustLevel: session.trustLevel,
          hint: 'Complete step-up authentication to perform this operation',
        });
        return;
      }

      // UNVERIFIED: Require step-up authentication
      if (session.trustLevel === SessionTrustLevel.UNVERIFIED) {
        res.status(403).json({
          error: 'Forbidden',
          message: 'Step-up authentication required for sensitive operations',
          currentTrustLevel: session.trustLevel,
          requiresStepUp: true,
          hint: 'Initiate step-up authentication to verify your identity',
        });
        return;
      }

      // HIGH_RISK: Deny access
      if (session.trustLevel === SessionTrustLevel.HIGH_RISK) {
        res.status(403).json({
          error: 'Forbidden',
          message: 'Sensitive operations are not allowed for high risk sessions',
          currentTrustLevel: session.trustLevel,
          hint: 'Your session has been flagged as high risk',
        });
        return;
      }

      // FULL_TRUST: Allow operation
      next();
    } catch (error) {
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to validate session',
      });
    }
  };
}

/**
 * Factory function to create middleware instance
 */
export function createAccessControlMiddleware(
  sessionManager: SessionManager
): AccessControlMiddleware {
  return new AccessControlMiddleware(sessionManager);
}
