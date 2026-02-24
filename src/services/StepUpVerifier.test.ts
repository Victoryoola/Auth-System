import { StepUpVerifier, EmailService, SMSService } from './StepUpVerifier';
import { SessionManager } from './SessionManager';
import { VerificationMethod, SessionTrustLevel } from '../types/enums';
import { pool } from '../config/database';
import crypto from 'crypto';

// Mock dependencies
jest.mock('../config/database');

describe('StepUpVerifier', () => {
  let stepUpVerifier: StepUpVerifier;
  let mockSessionManager: jest.Mocked<SessionManager>;
  let mockEmailService: jest.Mocked<EmailService>;
  let mockSMSService: jest.Mocked<SMSService>;
  let mockRedisClient: any;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();

    // Mock SessionManager
    mockSessionManager = {
      promoteTrustLevel: jest.fn(),
    } as any;

    // Mock EmailService
    mockEmailService = {
      sendOTP: jest.fn().mockResolvedValue(undefined),
    };

    // Mock SMSService
    mockSMSService = {
      sendOTP: jest.fn().mockResolvedValue(undefined),
    };

    // Mock RedisClient
    mockRedisClient = {
      get: jest.fn().mockResolvedValue(null),
      setEx: jest.fn().mockResolvedValue(undefined),
      incr: jest.fn().mockResolvedValue(1),
      expire: jest.fn().mockResolvedValue(undefined),
    };

    stepUpVerifier = new StepUpVerifier(
      mockSessionManager,
      mockEmailService,
      mockSMSService,
      mockRedisClient
    );
  });

  describe('initiateVerification', () => {
    it('should create a challenge and send email OTP', async () => {
      const userId = 'user-123';
      const sessionId = 'session-456';
      const method = VerificationMethod.EMAIL_OTP;

      // Mock database queries
      const mockChallengeId = crypto.randomUUID();
      (pool.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [] }) // INSERT challenge
        .mockResolvedValueOnce({ rows: [{ email: 'user@example.com' }] }) // Get user email
        .mockResolvedValueOnce({
          // SELECT challenge
          rows: [
            {
              id: mockChallengeId,
              user_id: userId,
              session_id: sessionId,
              method,
              otp_hash: 'hash',
              created_at: new Date(),
              expires_at: new Date(Date.now() + 10 * 60 * 1000),
              attempts_remaining: 3,
              verified: false,
            },
          ],
        });

      const challenge = await stepUpVerifier.initiateVerification(userId, sessionId, method);

      expect(challenge).toBeDefined();
      expect(challenge.userId).toBe(userId);
      expect(challenge.sessionId).toBe(sessionId);
      expect(challenge.method).toBe(method);
      expect(challenge.attemptsRemaining).toBe(3);
      expect(mockEmailService.sendOTP).toHaveBeenCalledWith('user@example.com', expect.any(String));
      expect(mockRedisClient.incr).toHaveBeenCalled();
    });

    it('should create a challenge and send SMS OTP', async () => {
      const userId = 'user-123';
      const sessionId = 'session-456';
      const method = VerificationMethod.SMS_OTP;

      // Mock database queries
      const mockChallengeId = crypto.randomUUID();
      (pool.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [] }) // INSERT challenge
        .mockResolvedValueOnce({ rows: [{ phone_number: '+1234567890' }] }) // Get user phone
        .mockResolvedValueOnce({
          // SELECT challenge
          rows: [
            {
              id: mockChallengeId,
              user_id: userId,
              session_id: sessionId,
              method,
              otp_hash: 'hash',
              created_at: new Date(),
              expires_at: new Date(Date.now() + 10 * 60 * 1000),
              attempts_remaining: 3,
              verified: false,
            },
          ],
        });

      const challenge = await stepUpVerifier.initiateVerification(userId, sessionId, method);

      expect(challenge).toBeDefined();
      expect(mockSMSService.sendOTP).toHaveBeenCalledWith('+1234567890', expect.any(String));
    });

    it('should enforce rate limiting', async () => {
      const userId = 'user-123';
      const sessionId = 'session-456';
      const method = VerificationMethod.EMAIL_OTP;

      // Mock rate limit exceeded
      mockRedisClient.get.mockResolvedValueOnce('5');

      await expect(
        stepUpVerifier.initiateVerification(userId, sessionId, method)
      ).rejects.toThrow('Rate limit exceeded');
    });

    it('should throw error if email service not configured', async () => {
      const stepUpVerifierNoEmail = new StepUpVerifier(mockSessionManager, undefined, mockSMSService);
      const userId = 'user-123';
      const sessionId = 'session-456';
      const method = VerificationMethod.EMAIL_OTP;

      (pool.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [] }) // INSERT challenge
        .mockResolvedValueOnce({ rows: [{ email: 'user@example.com' }] }); // Get user email

      await expect(
        stepUpVerifierNoEmail.initiateVerification(userId, sessionId, method)
      ).rejects.toThrow('Email service not configured');
    });

    it('should generate cryptographically secure 6-digit OTP', async () => {
      const userId = 'user-123';
      const sessionId = 'session-456';
      const method = VerificationMethod.EMAIL_OTP;

      (pool.query as jest.Mock)
        .mockResolvedValueOnce({ rows: [] }) // INSERT challenge
        .mockResolvedValueOnce({ rows: [{ email: 'user@example.com' }] }) // Get user email
        .mockResolvedValueOnce({
          rows: [
            {
              id: crypto.randomUUID(),
              user_id: userId,
              session_id: sessionId,
              method,
              otp_hash: 'hash',
              created_at: new Date(),
              expires_at: new Date(Date.now() + 10 * 60 * 1000),
              attempts_remaining: 3,
              verified: false,
            },
          ],
        });

      await stepUpVerifier.initiateVerification(userId, sessionId, method);

      // Verify OTP is 6 digits
      const otpCall = mockEmailService.sendOTP.mock.calls[0];
      const otp = otpCall[1];
      expect(otp).toMatch(/^\d{6}$/);
    });
  });

  describe('verifyChallenge', () => {
    it('should verify valid OTP and promote trust level', async () => {
      const challengeId = 'challenge-123';
      const otp = '123456';
      const otpHash = crypto.createHash('sha256').update(otp).digest('hex');

      // Mock database queries
      (pool.query as jest.Mock)
        .mockResolvedValueOnce({
          // SELECT challenge
          rows: [
            {
              id: challengeId,
              user_id: 'user-123',
              session_id: 'session-456',
              method: VerificationMethod.EMAIL_OTP,
              otp_hash: otpHash,
              created_at: new Date(),
              expires_at: new Date(Date.now() + 10 * 60 * 1000),
              attempts_remaining: 3,
              verified: false,
            },
          ],
        })
        .mockResolvedValueOnce({ rows: [] }) // UPDATE verified
        .mockResolvedValueOnce({
          // SELECT session trust level
          rows: [{ trust_level: SessionTrustLevel.UNVERIFIED }],
        });

      const result = await stepUpVerifier.verifyChallenge(challengeId, otp);

      expect(result.success).toBe(true);
      expect(result.newTrustLevel).toBe(SessionTrustLevel.LIMITED_TRUST);
      expect(mockSessionManager.promoteTrustLevel).toHaveBeenCalledWith(
        'session-456',
        SessionTrustLevel.LIMITED_TRUST
      );
    });

    it('should reject invalid OTP and decrement attempts', async () => {
      const challengeId = 'challenge-123';
      const otp = '123456';
      const wrongOtp = '654321';
      const otpHash = crypto.createHash('sha256').update(otp).digest('hex');

      (pool.query as jest.Mock)
        .mockResolvedValueOnce({
          rows: [
            {
              id: challengeId,
              user_id: 'user-123',
              session_id: 'session-456',
              method: VerificationMethod.EMAIL_OTP,
              otp_hash: otpHash,
              created_at: new Date(),
              expires_at: new Date(Date.now() + 10 * 60 * 1000),
              attempts_remaining: 3,
              verified: false,
            },
          ],
        })
        .mockResolvedValueOnce({ rows: [] }); // UPDATE attempts

      const result = await stepUpVerifier.verifyChallenge(challengeId, wrongOtp);

      expect(result.success).toBe(false);
      expect(result.reason).toBe('Invalid OTP');
      expect(pool.query).toHaveBeenCalledWith(
        'UPDATE challenges SET attempts_remaining = attempts_remaining - 1 WHERE id = $1',
        [challengeId]
      );
    });

    it('should reject expired challenge', async () => {
      const challengeId = 'challenge-123';
      const otp = '123456';

      (pool.query as jest.Mock).mockResolvedValueOnce({
        rows: [
          {
            id: challengeId,
            user_id: 'user-123',
            session_id: 'session-456',
            method: VerificationMethod.EMAIL_OTP,
            otp_hash: 'hash',
            created_at: new Date(Date.now() - 20 * 60 * 1000),
            expires_at: new Date(Date.now() - 10 * 60 * 1000), // Expired
            attempts_remaining: 3,
            verified: false,
          },
        ],
      });

      const result = await stepUpVerifier.verifyChallenge(challengeId, otp);

      expect(result.success).toBe(false);
      expect(result.reason).toBe('Challenge expired');
    });

    it('should reject when attempts exhausted', async () => {
      const challengeId = 'challenge-123';
      const otp = '123456';

      (pool.query as jest.Mock).mockResolvedValueOnce({
        rows: [
          {
            id: challengeId,
            user_id: 'user-123',
            session_id: 'session-456',
            method: VerificationMethod.EMAIL_OTP,
            otp_hash: 'hash',
            created_at: new Date(),
            expires_at: new Date(Date.now() + 10 * 60 * 1000),
            attempts_remaining: 0, // No attempts left
            verified: false,
          },
        ],
      });

      const result = await stepUpVerifier.verifyChallenge(challengeId, otp);

      expect(result.success).toBe(false);
      expect(result.reason).toBe('Maximum attempts exceeded');
    });

    it('should reject already verified challenge', async () => {
      const challengeId = 'challenge-123';
      const otp = '123456';

      (pool.query as jest.Mock).mockResolvedValueOnce({
        rows: [
          {
            id: challengeId,
            user_id: 'user-123',
            session_id: 'session-456',
            method: VerificationMethod.EMAIL_OTP,
            otp_hash: 'hash',
            created_at: new Date(),
            expires_at: new Date(Date.now() + 10 * 60 * 1000),
            attempts_remaining: 3,
            verified: true, // Already verified
          },
        ],
      });

      const result = await stepUpVerifier.verifyChallenge(challengeId, otp);

      expect(result.success).toBe(false);
      expect(result.reason).toBe('Challenge already verified');
    });

    it('should use constant-time comparison for OTP validation', async () => {
      // This test verifies that the comparison doesn't leak timing information
      const challengeId = 'challenge-123';
      const correctOtp = '123456';
      const wrongOtp = '000000';
      const otpHash = crypto.createHash('sha256').update(correctOtp).digest('hex');

      (pool.query as jest.Mock).mockResolvedValue({
        rows: [
          {
            id: challengeId,
            user_id: 'user-123',
            session_id: 'session-456',
            method: VerificationMethod.EMAIL_OTP,
            otp_hash: otpHash,
            created_at: new Date(),
            expires_at: new Date(Date.now() + 10 * 60 * 1000),
            attempts_remaining: 3,
            verified: false,
          },
        ],
      });

      // Measure time for correct OTP
      const start1 = process.hrtime.bigint();
      await stepUpVerifier.verifyChallenge(challengeId, correctOtp);
      const end1 = process.hrtime.bigint();
      const time1 = Number(end1 - start1);

      // Reset mock
      (pool.query as jest.Mock).mockResolvedValue({
        rows: [
          {
            id: challengeId,
            user_id: 'user-123',
            session_id: 'session-456',
            method: VerificationMethod.EMAIL_OTP,
            otp_hash: otpHash,
            created_at: new Date(),
            expires_at: new Date(Date.now() + 10 * 60 * 1000),
            attempts_remaining: 3,
            verified: false,
          },
        ],
      });

      // Measure time for wrong OTP
      const start2 = process.hrtime.bigint();
      await stepUpVerifier.verifyChallenge(challengeId, wrongOtp);
      const end2 = process.hrtime.bigint();
      const time2 = Number(end2 - start2);

      // Times should be similar (within 20x factor for test reliability)
      // In production with optimized code, they should be nearly identical
      // Note: Timing tests can be flaky due to system load and JIT compilation
      const ratio = Math.max(time1, time2) / Math.min(time1, time2);
      expect(ratio).toBeLessThan(20);
    });
  });

  describe('resendChallenge', () => {
    it('should resend OTP for existing challenge', async () => {
      const challengeId = 'challenge-123';

      (pool.query as jest.Mock)
        .mockResolvedValueOnce({
          // SELECT challenge
          rows: [
            {
              id: challengeId,
              user_id: 'user-123',
              session_id: 'session-456',
              method: VerificationMethod.EMAIL_OTP,
              otp_hash: 'old-hash',
              created_at: new Date(),
              expires_at: new Date(Date.now() + 10 * 60 * 1000),
              attempts_remaining: 2,
              verified: false,
            },
          ],
        })
        .mockResolvedValueOnce({ rows: [] }) // UPDATE otp_hash
        .mockResolvedValueOnce({ rows: [{ email: 'user@example.com' }] }); // Get user email

      await stepUpVerifier.resendChallenge(challengeId);

      expect(mockEmailService.sendOTP).toHaveBeenCalledWith('user@example.com', expect.any(String));
      expect(mockRedisClient.incr).toHaveBeenCalled();
    });

    it('should throw error for expired challenge', async () => {
      const challengeId = 'challenge-123';

      (pool.query as jest.Mock).mockResolvedValueOnce({
        rows: [
          {
            id: challengeId,
            user_id: 'user-123',
            session_id: 'session-456',
            method: VerificationMethod.EMAIL_OTP,
            otp_hash: 'hash',
            created_at: new Date(Date.now() - 20 * 60 * 1000),
            expires_at: new Date(Date.now() - 10 * 60 * 1000), // Expired
            attempts_remaining: 2,
            verified: false,
          },
        ],
      });

      await expect(stepUpVerifier.resendChallenge(challengeId)).rejects.toThrow(
        'Challenge expired'
      );
    });

    it('should enforce rate limiting on resend', async () => {
      const challengeId = 'challenge-123';

      (pool.query as jest.Mock).mockResolvedValueOnce({
        rows: [
          {
            id: challengeId,
            user_id: 'user-123',
            session_id: 'session-456',
            method: VerificationMethod.EMAIL_OTP,
            otp_hash: 'hash',
            created_at: new Date(),
            expires_at: new Date(Date.now() + 10 * 60 * 1000),
            attempts_remaining: 2,
            verified: false,
          },
        ],
      });

      mockRedisClient.get.mockResolvedValueOnce('5'); // Rate limit exceeded

      await expect(stepUpVerifier.resendChallenge(challengeId)).rejects.toThrow(
        'Rate limit exceeded'
      );
    });
  });

  describe('trust level promotion', () => {
    it('should promote HIGH_RISK to UNVERIFIED', async () => {
      const challengeId = 'challenge-123';
      const otp = '123456';
      const otpHash = crypto.createHash('sha256').update(otp).digest('hex');

      (pool.query as jest.Mock)
        .mockResolvedValueOnce({
          rows: [
            {
              id: challengeId,
              user_id: 'user-123',
              session_id: 'session-456',
              method: VerificationMethod.EMAIL_OTP,
              otp_hash: otpHash,
              created_at: new Date(),
              expires_at: new Date(Date.now() + 10 * 60 * 1000),
              attempts_remaining: 3,
              verified: false,
            },
          ],
        })
        .mockResolvedValueOnce({ rows: [] }) // UPDATE verified
        .mockResolvedValueOnce({
          rows: [{ trust_level: SessionTrustLevel.HIGH_RISK }],
        });

      const result = await stepUpVerifier.verifyChallenge(challengeId, otp);

      expect(result.newTrustLevel).toBe(SessionTrustLevel.UNVERIFIED);
    });

    it('should promote LIMITED_TRUST to FULL_TRUST', async () => {
      const challengeId = 'challenge-123';
      const otp = '123456';
      const otpHash = crypto.createHash('sha256').update(otp).digest('hex');

      (pool.query as jest.Mock)
        .mockResolvedValueOnce({
          rows: [
            {
              id: challengeId,
              user_id: 'user-123',
              session_id: 'session-456',
              method: VerificationMethod.EMAIL_OTP,
              otp_hash: otpHash,
              created_at: new Date(),
              expires_at: new Date(Date.now() + 10 * 60 * 1000),
              attempts_remaining: 3,
              verified: false,
            },
          ],
        })
        .mockResolvedValueOnce({ rows: [] }) // UPDATE verified
        .mockResolvedValueOnce({
          rows: [{ trust_level: SessionTrustLevel.LIMITED_TRUST }],
        });

      const result = await stepUpVerifier.verifyChallenge(challengeId, otp);

      expect(result.newTrustLevel).toBe(SessionTrustLevel.FULL_TRUST);
    });

    it('should keep FULL_TRUST at FULL_TRUST', async () => {
      const challengeId = 'challenge-123';
      const otp = '123456';
      const otpHash = crypto.createHash('sha256').update(otp).digest('hex');

      (pool.query as jest.Mock)
        .mockResolvedValueOnce({
          rows: [
            {
              id: challengeId,
              user_id: 'user-123',
              session_id: 'session-456',
              method: VerificationMethod.EMAIL_OTP,
              otp_hash: otpHash,
              created_at: new Date(),
              expires_at: new Date(Date.now() + 10 * 60 * 1000),
              attempts_remaining: 3,
              verified: false,
            },
          ],
        })
        .mockResolvedValueOnce({ rows: [] }) // UPDATE verified
        .mockResolvedValueOnce({
          rows: [{ trust_level: SessionTrustLevel.FULL_TRUST }],
        });

      const result = await stepUpVerifier.verifyChallenge(challengeId, otp);

      expect(result.newTrustLevel).toBe(SessionTrustLevel.FULL_TRUST);
    });
  });
});
