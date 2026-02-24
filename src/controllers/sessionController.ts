import { Response } from 'express';
import { SessionManager } from '../services/SessionManager';
import { param, validationResult } from 'express-validator';
import { AuthenticatedRequest } from '../middleware/accessControl';

/**
 * Session Management Controller
 * Handles session listing and termination
 */
export class SessionController {
  constructor(private sessionManager: SessionManager) {}

  /**
   * GET /sessions
   * List all active sessions for the authenticated user
   */
  async listSessions(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.session) {
        res.status(401).json({
          error: 'unauthorized',
          message: 'Authentication required',
        });
        return;
      }

      const { userId } = req.session;

      const sessions = await this.sessionManager.getActiveSessions(userId);

      // Format response (exclude sensitive token hashes)
      const formattedSessions = sessions.map(session => ({
        id: session.id,
        trustLevel: session.trustLevel,
        deviceIdentity: session.deviceIdentity,
        ipAddress: session.ipAddress,
        createdAt: session.createdAt,
        lastActivity: session.lastActivity,
        accessTokenExpiry: session.accessTokenExpiry,
        refreshTokenExpiry: session.refreshTokenExpiry,
      }));

      res.status(200).json({
        sessions: formattedSessions,
        total: formattedSessions.length,
      });
    } catch (error) {
      this.handleSessionError(error, res);
    }
  }

  /**
   * DELETE /sessions/:id
   * Terminate a specific session
   */
  async terminateSession(req: AuthenticatedRequest, res: Response): Promise<void> {
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
      const { id: sessionId } = req.params;

      // Get all user sessions to verify ownership
      const sessions = await this.sessionManager.getActiveSessions(userId);
      const sessionToTerminate = sessions.find(s => s.id === sessionId);

      if (!sessionToTerminate) {
        res.status(404).json({
          error: 'session_not_found',
          message: 'Session not found or already terminated',
        });
        return;
      }

      // Verify user owns this session
      if (sessionToTerminate.userId !== userId) {
        res.status(403).json({
          error: 'forbidden',
          message: 'You do not have permission to terminate this session',
        });
        return;
      }

      // Revoke session
      await this.sessionManager.revokeSession(sessionId);

      res.status(200).json({
        message: 'Session terminated successfully',
        sessionId,
      });
    } catch (error) {
      this.handleSessionError(error, res);
    }
  }

  /**
   * Handle session management errors
   */
  private handleSessionError(error: unknown, res: Response): void {
    if (error instanceof Error) {
      res.status(500).json({
        error: 'session_operation_failed',
        message: 'Session operation failed',
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
 * Validation rules for session ID parameter
 */
export const sessionIdValidation = [
  param('id').isUUID().withMessage('Valid session ID is required'),
];
