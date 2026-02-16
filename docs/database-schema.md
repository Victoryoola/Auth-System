# Database Schema Documentation

## Overview

The AADE database schema consists of 6 main tables with proper indexing, partitioning, and referential integrity.

## Tables

### 1. users
**Purpose**: Stores users' authentication credentials and account status

**Columns**:
- `id` (UUID, PK) - Unique user identifier
- `email` (VARCHAR, UNIQUE) - User email address
- `password_hash` (VARCHAR) - Argon2id hashed password
- `mfa_enabled` (BOOLEAN) - MFA status
- `mfa_secret` (VARCHAR) - TOTP secret for MFA
- `created_at` (TIMESTAMP) - Account creation time
- `updated_at` (TIMESTAMP) - Last update time (auto-updated)
- `last_login_at` (TIMESTAMP) - Last successful login
- `failed_login_attempts` (INTEGER) - Failed login counter
- `last_failed_login_at` (TIMESTAMP) - Last failed login time
- `account_locked` (BOOLEAN) - Account lock status
- `lockout_until` (TIMESTAMP) - Lock expiration time

**Indexes**:
- Primary key on `id`
- Unique index on `email`
- Index on `account_locked`
- Conditional index on `lockout_until`

**Triggers**:
- Auto-update `updated_at` on row modification

---

### 2. devices
**Purpose**: Device recognition and trust management

**Columns**:
- `id` (UUID, PK) - Unique device identifier
- `user_id` (UUID, FK → users) - Owner user
- `identity` (VARCHAR) - SHA-256 hash of device characteristics
- `trust_status` (VARCHAR) - TRUSTED, UNTRUSTED, or PENDING
- `revoked` (BOOLEAN) - Revocation status
- `first_seen` (TIMESTAMP) - First login from device
- `last_seen` (TIMESTAMP) - Most recent login
- `device_type` (VARCHAR) - Device type (mobile, desktop, tablet)
- `browser` (VARCHAR) - Browser name and version
- `operating_system` (VARCHAR) - OS name and version
- `last_ip_address` (INET) - Last IP address used

**Indexes**:
- Primary key on `id`
- Index on `user_id`
- Index on `identity`
- Composite index on `(user_id, identity)`
- Index on `trust_status`
- Index on `revoked`

**Constraints**:
- Foreign key to `users` with CASCADE delete
- Check constraint on `trust_status` values

---

### 3. sessions
**Purpose**: Active session management with trust levels

**Columns**:
- `id` (UUID, PK) - Unique session identifier
- `user_id` (UUID, FK → users) - Session owner
- `trust_level` (VARCHAR) - FULL_TRUST, LIMITED_TRUST, UNVERIFIED, HIGH_RISK
- `device_identity` (VARCHAR) - Device identity hash
- `access_token_hash` (VARCHAR) - Hashed access token
- `refresh_token_hash` (VARCHAR) - Hashed refresh token
- `refresh_token_family` (VARCHAR) - Token family for replay detection
- `access_token_expiry` (TIMESTAMP) - Access token expiration
- `refresh_token_expiry` (TIMESTAMP) - Refresh token expiration
- `created_at` (TIMESTAMP) - Session creation time
- `last_activity` (TIMESTAMP) - Last activity timestamp
- `ip_address` (INET) - Session IP address
- `revoked` (BOOLEAN) - Revocation status

**Indexes**:
- Primary key on `id`
- Index on `user_id`
- Index on `refresh_token_hash`
- Index on `device_identity`
- Index on `revoked`
- Index on `refresh_token_expiry`
- Composite index on `(user_id, revoked)` for active sessions

**Constraints**:
- Foreign key to `users` with CASCADE delete
- Check constraint on `trust_level` values

---

### 4. risk_evaluations (PARTITIONED)
**Purpose**: Risk assessment history

**Partitioning**: By month using `timestamp` column

**Columns**:
- `id` (UUID, PK) - Unique evaluation identifier
- `user_id` (UUID, FK → users) - User being evaluated
- `device_identity` (VARCHAR) - Device identity hash
- `ip_address` (INET) - Login IP address
- `timestamp` (TIMESTAMP, PARTITION KEY) - Evaluation time
- `risk_score` (INTEGER) - Overall risk score (0-100)
- `trust_level` (VARCHAR) - Assigned trust level
- `device_familiarity` (INTEGER) - Device factor contribution
- `geographic_anomaly` (INTEGER) - Location factor contribution
- `ip_reputation` (INTEGER) - IP factor contribution
- `login_velocity` (INTEGER) - Velocity factor contribution
- `failed_attempts` (INTEGER) - Failed attempts factor contribution

**Indexes**:
- Composite primary key on `(id, timestamp)`
- Composite index on `(user_id, timestamp DESC)`
- Index on `timestamp DESC`
- Index on `device_identity`

**Constraints**:
- Foreign key to `users` with CASCADE delete
- Check constraint on `trust_level` values
- Check constraint on `risk_score` range (0-100)

**Partitions**:
- Monthly partitions (e.g., `risk_evaluations_2024_01`)
- Default partition for overflow

---

### 5. challenges
**Purpose**: Step-up authentication challenges

**Columns**:
- `id` (UUID, PK) - Unique challenge identifier
- `user_id` (UUID, FK → users) - Challenge owner
- `session_id` (UUID, FK → sessions) - Associated session
- `method` (VARCHAR) - EMAIL_OTP, SMS_OTP, or AUTHENTICATOR_APP
- `otp_hash` (VARCHAR) - Hashed OTP (not plaintext)
- `created_at` (TIMESTAMP) - Challenge creation time
- `expires_at` (TIMESTAMP) - Challenge expiration
- `attempts_remaining` (INTEGER) - Remaining verification attempts
- `verified` (BOOLEAN) - Verification status

**Indexes**:
- Primary key on `id`
- Index on `user_id`
- Index on `session_id`
- Index on `expires_at`
- Index on `verified`

**Constraints**:
- Foreign key to `users` with CASCADE delete
- Foreign key to `sessions` with CASCADE delete
- Check constraint on `method` values
- Check constraint on `attempts_remaining` >= 0

---

### 6. audit_logs (PARTITIONED)
**Purpose**: Security event logging

**Partitioning**: By month using `timestamp` column

**Columns**:
- `id` (UUID, PK) - Unique log identifier
- `timestamp` (TIMESTAMP, PARTITION KEY) - Event time
- `event_type` (VARCHAR) - Event type (e.g., LOGIN_ATTEMPT)
- `user_id` (UUID) - User involved in event
- `session_id` (UUID) - Associated session (optional)
- `device_identity` (VARCHAR) - Device identity (optional)
- `ip_address` (INET) - Event IP address (optional)
- `success` (BOOLEAN) - Event success status
- `details` (JSONB) - Additional event details
- `encrypted_fields` (TEXT[]) - List of encrypted field names

**Indexes**:
- Composite primary key on `(id, timestamp)`
- Composite index on `(user_id, timestamp DESC)`
- Composite index on `(event_type, timestamp DESC)`
- Index on `timestamp DESC`
- Conditional index on `session_id`

**Partitions**:
- Monthly partitions (e.g., `audit_logs_2024_01`)
- Default partition for overflow

---

## TypeScript Models

All database tables have corresponding TypeScript interfaces in `src/models/`:

- `User.ts` - User model with create/update types
- `Device.ts` - Device model with metadata interface
- `Session.ts` - Session model with trust levels
- `RiskEvaluation.ts` - Risk evaluation with factors
- `Challenge.ts` - Challenge model with verification methods
- `AuditLog.ts` - Audit log with filters

## Enums

Defined in `src/types/enums.ts`:

- `SessionTrustLevel` - FULL_TRUST, LIMITED_TRUST, UNVERIFIED, HIGH_RISK
- `TrustStatus` - TRUSTED, UNTRUSTED, PENDING
- `VerificationMethod` - EMAIL_OTP, SMS_OTP, AUTHENTICATOR_APP

## Database Configuration

Connection configuration in `src/config/database.ts`:

- PostgreSQL connection pool
- Connection testing utility
- Graceful shutdown support

## Running Migrations

```bash
# Run all migrations
npm run migrate

# Or manually with psql
psql -U postgres -d aade_db -f migrations/001_create_users_table.sql
# ... continue with other migrations
```

## Partition Management

New partitions should be created monthly:

```sql
-- Example: Create April 2024 partitions
CREATE TABLE audit_logs_2024_04 PARTITION OF audit_logs
    FOR VALUES FROM ('2024-04-01') TO ('2024-05-01');

CREATE TABLE risk_evaluations_2024_04 PARTITION OF risk_evaluations
    FOR VALUES FROM ('2024-04-01') TO ('2024-05-01');
```

## Data Retention

Recommended retention policies:

- `users`: Indefinite (until account deletion)
- `devices`: Indefinite (until user revokes or deletes account)
- `sessions`: 7 days after expiration
- `risk_evaluations`: 30 days (partitioned for easy cleanup)
- `challenges`: 24 hours after expiration
- `audit_logs`: 90 days (partitioned for easy cleanup)

## Performance Considerations

1. **Partitioning**: `audit_logs` and `risk_evaluations` are partitioned by month for:
   - Faster queries on recent data
   - Easier data archival/deletion
   - Better index performance

2. **Indexes**: All tables have indexes on:
   - Primary keys
   - Foreign keys
   - Common query patterns
   - Timestamp columns for time-based queries

3. **Connection Pooling**: PostgreSQL connection pool configured with:
   - Max 20 connections
   - 30-second idle timeout
   - 2-second connection timeout

## Security Features

1. **Password Storage**: Argon2id hashing (implemented in application layer)
2. **Token Storage**: Only hashes stored, never plaintext tokens
3. **OTP Storage**: Only hashes stored, never plaintext OTPs
4. **Encrypted Fields**: Sensitive audit log fields encrypted before storage
5. **Referential Integrity**: CASCADE deletes ensure data consistency
6. **Check Constraints**: Validate enum values and ranges at database level

## Next Steps

With the database schema complete, you can now:

1. Implement the Device Registry service (Task 3)
2. Implement the Risk Engine service (Task 4)
3. Implement the Session Manager service (Task 6)
