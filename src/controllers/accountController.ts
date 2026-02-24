import { Request, Response } from 'express';
import { AccountService } from '../services/AccountService';
import { body, validationResult } from 'express-validator';

/**
 * Account Controller
 * Handles account deletion and user preferences
 */
export class AccountController {
  constructor(private accountService: AccountService) {}

  /**
   * DELETE /account
   * Delete user account and all associated data
   */
  async deleteAccount(req: Request, res: Response): Promise<void> {
    try {
      // In a real implementation, userId would come from authenticated session
      const userId = req.body.userId;

      if (!userId) {
        res.status(400).json({
          error: 'validation_error',
          message: 'User ID is required',
        });
        return;
      }

      await this.accountService.deleteAccount(userId);

      res.status(200).json({
        message: 'Account deleted successfully',
      });
    } catch (error) {
      if (error instanceof Error) {
        res.status(500).json({
          error: 'account_deletion_failed',
          message: error.message,
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
   * PUT /account/preferences
   * Update user preferences including device tracking
   */
  async updatePreferences(req: Request, res: Response): Promise<void> {
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

      // In a real implementation, userId would come from authenticated session
      const userId = req.body.userId;
      const { deviceTrackingEnabled } = req.body;

      if (!userId) {
        res.status(400).json({
          error: 'validation_error',
          message: 'User ID is required',
        });
        return;
      }

      if (typeof deviceTrackingEnabled === 'boolean') {
        await this.accountService.updateDeviceTrackingPreference(
          userId,
          deviceTrackingEnabled
        );
      }

      res.status(200).json({
        message: 'Preferences updated successfully',
        deviceTrackingEnabled,
      });
    } catch (error) {
      if (error instanceof Error) {
        if (error.message === 'User not found') {
          res.status(404).json({
            error: 'user_not_found',
            message: 'User not found',
          });
        } else {
          res.status(500).json({
            error: 'preferences_update_failed',
            message: error.message,
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
}

/**
 * Validation rules for preferences update endpoint
 */
export const updatePreferencesValidation = [
  body('userId').isUUID().withMessage('Valid user ID is required'),
  body('deviceTrackingEnabled')
    .optional()
    .isBoolean()
    .withMessage('Device tracking enabled must be a boolean'),
];
