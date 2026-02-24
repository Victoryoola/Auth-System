import { Router, Request, Response } from 'express';
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
  router.delete('/', (req: Request, res: Response) => controller.deleteAccount(req, res));

  /**
   * PUT /account/preferences
   * Update user preferences (device tracking opt-out)
   */
  router.put('/preferences', updatePreferencesValidation, (req: Request, res: Response) =>
    controller.updatePreferences(req, res)
  );

  return router;
}
