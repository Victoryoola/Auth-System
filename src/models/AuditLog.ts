/**
 * Audit log model for security event tracking
 */
export interface AuditLog {
  id: string;
  timestamp: Date;
  eventType: string;
  userId: string;
  sessionId?: string;
  deviceIdentity?: string;
  ipAddress?: string;
  success: boolean;
  details: Record<string, unknown>;
  encryptedFields: string[];
}

/**
 * Audit log creation input
 */
export interface CreateAuditLogInput {
  eventType: string;
  userId: string;
  sessionId?: string;
  deviceIdentity?: string;
  ipAddress?: string;
  success: boolean;
  details: Record<string, unknown>;
  encryptedFields?: string[];
}

/**
 * Audit log query filters
 */
export interface AuditLogFilters {
  eventType?: string;
  startDate?: Date;
  endDate?: Date;
  success?: boolean;
  limit?: number;
  offset?: number;
}
