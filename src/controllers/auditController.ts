import { Response } from 'express';
import { AuditLogger } from '../services/AuditLogger';
import { query, validationResult } from 'express-validator';
import { AuthenticatedRequest } from '../middleware/accessControl';

/**
 * Audit Log Controller
 * Handles audit log retrieval with user isolation and filtering
 */
export class AuditController {
  constructor(private auditLogger: AuditLogger) {}

  /**
   * GET /audit-logs
   * Retrieve audit logs for the authenticated user with optional filters
   */
  async getLogs(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.status(400).json({
          error: 'validation_error',
          message: 'Invalid query parameters',
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

      // Extract query parameters
      const {
        eventType,
        startDate,
        endDate,
        success,
        limit = '50',
        offset = '0',
      } = req.query;

      // Build filters
      const filters: any = {
        limit: parseInt(limit as string, 10),
        offset: parseInt(offset as string, 10),
      };

      if (eventType) {
        filters.eventType = eventType as string;
      }

      if (startDate) {
        filters.startDate = new Date(startDate as string);
      }

      if (endDate) {
        filters.endDate = new Date(endDate as string);
      }

      if (success !== undefined) {
        filters.success = success === 'true';
      }

      // Query logs with user isolation
      const logs = await this.auditLogger.queryLogs(userId, filters);

      res.status(200).json({
        logs,
        total: logs.length,
        limit: filters.limit,
        offset: filters.offset,
      });
    } catch (error) {
      this.handleAuditError(error, res);
    }
  }

  /**
   * Handle audit log errors
   */
  private handleAuditError(error: unknown, res: Response): void {
    if (error instanceof Error) {
      res.status(500).json({
        error: 'audit_query_failed',
        message: 'Failed to retrieve audit logs',
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
 * Validation rules for audit log query parameters
 */
export const auditLogsValidation = [
  query('eventType')
    .optional()
    .isIn(['AUTH_ATTEMPT', 'RISK_EVALUATION', 'DEVICE_CHANGE', 'SUSPICIOUS_ACTIVITY', 'STEP_UP_ATTEMPT'])
    .withMessage('Invalid event type'),
  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('Start date must be a valid ISO 8601 date'),
  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('End date must be a valid ISO 8601 date'),
  query('success')
    .optional()
    .isBoolean()
    .withMessage('Success must be a boolean value'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('offset')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Offset must be a non-negative integer'),
];
