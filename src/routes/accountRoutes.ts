import { Router } from 'express';
import { AccountController, updatePreferencesValidation } from '../controllers/accountController';
import { AccountService } from '../services/AccountService';

/**
 * Create account management routes
 */
export function createAccountRoutes(accountService: AccountService): Router {
  const router = Router();
  const controller = new AccountController(accountService);

  /**
   * DELETE /account
   * Delete user account and all associated data
   */
  router.delete('/', (req, res) => controller.deleteAccount(req, res));

  /**
   * PUT /account/preferences
   * Update user preferences (device tracking opt-out)
   */
  router.put('/preferences', updatePreferencesValidation, (req, res) =>
    controller.updatePreferences(req, res)
  );

  return router;
}
