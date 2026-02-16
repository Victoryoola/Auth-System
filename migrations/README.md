# Database Migrations

This directory contains SQL migration scripts for the AADE database schema.

## Migration Order

Migrations are executed in numerical order:

1. `001_create_users_table.sql` - Users table with authentication data
2. `002_create_devices_table.sql` - Devices table with trust status
3. `003_create_sessions_table.sql` - Sessions table with tokens
4. `004_create_risk_evaluations_table.sql` - Risk evaluations (partitioned)
5. `005_create_challenges_table.sql` - Step-up authentication challenges
6. `006_create_audit_logs_table.sql` - Audit logs (partitioned)

## Running Migrations

### Prerequisites

1. PostgreSQL 14+ installed and running
2. Database created:
   ```sql
   CREATE DATABASE aade_db;
   ```

3. Environment variables configured in `.env`:
   ```
   DB_HOST=localhost
   DB_PORT=5432
   DB_NAME=aade_db
   DB_USER=postgres
   DB_PASSWORD=your_password
   ```

### Execute Migrations

Run all migrations:
```bash
npm run migrate
```

Or manually with psql:
```bash
psql -U postgres -d aade_db -f migrations/001_create_users_table.sql
psql -U postgres -d aade_db -f migrations/002_create_devices_table.sql
# ... and so on
```

## Schema Overview

### Tables

**users**
- Primary authentication table
- Stores email, password hash, MFA settings
- Tracks failed login attempts and account lockout

**devices**
- Device recognition and trust management
- Stores device identity hash and metadata
- Supports device revocation

**sessions**
- Active session management
- Stores token hashes and trust levels
- Supports token rotation and replay protection

**risk_evaluations** (partitioned by month)
- Risk assessment history
- Stores risk scores and contributing factors
- Partitioned for performance

**challenges**
- Step-up authentication challenges
- Stores OTP hashes and verification status
- Tracks remaining attempts

**audit_logs** (partitioned by month)
- Security event logging
- Stores authentication and security events
- Partitioned for performance

### Indexes

All tables have appropriate indexes for:
- Primary key lookups
- Foreign key relationships
- Common query patterns
- Timestamp-based queries

### Partitioning

`risk_evaluations` and `audit_logs` are partitioned by month for:
- Improved query performance
- Easier data retention management
- Efficient archival

## Partition Management

New partitions should be created monthly. Example:

```sql
-- Create partition for April 2024
CREATE TABLE audit_logs_2024_04 PARTITION OF audit_logs
    FOR VALUES FROM ('2024-04-01') TO ('2024-05-01');

CREATE TABLE risk_evaluations_2024_04 PARTITION OF risk_evaluations
    FOR VALUES FROM ('2024-04-01') TO ('2024-05-01');
```

## Rollback

To rollback migrations, drop tables in reverse order:

```sql
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS challenges CASCADE;
DROP TABLE IF EXISTS risk_evaluations CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS devices CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP FUNCTION IF EXISTS update_updated_at_column CASCADE;
```

## Notes

- All timestamps use `TIMESTAMP WITH TIME ZONE` for timezone awareness
- UUIDs are used for primary keys for better distribution
- Foreign keys have `ON DELETE CASCADE` for referential integrity
- Check constraints ensure data validity
- Comments document table and column purposes
