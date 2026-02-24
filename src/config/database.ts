import { Pool, PoolConfig } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

/**
 * PostgreSQL connection configuration
 * Uses test database when NODE_ENV is 'test'
 */
const isTestEnv = process.env.NODE_ENV === 'test';

const poolConfig: PoolConfig = {
  host: isTestEnv ? (process.env.TEST_DB_HOST || process.env.DB_HOST || 'localhost') : (process.env.DB_HOST || 'localhost'),
  port: parseInt(isTestEnv ? (process.env.TEST_DB_PORT || process.env.DB_PORT || '5432') : (process.env.DB_PORT || '5432'), 10),
  database: isTestEnv ? (process.env.TEST_DB_NAME || 'aade_test_db') : (process.env.DB_NAME || 'aade_db'),
  user: isTestEnv ? (process.env.TEST_DB_USER || process.env.DB_USER || 'postgres') : (process.env.DB_USER || 'postgres'),
  password: isTestEnv ? (process.env.TEST_DB_PASSWORD || process.env.DB_PASSWORD) : process.env.DB_PASSWORD,
  max: 20, // Maximum number of clients in the pool
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
};

/**
 * PostgreSQL connection pool
 */
export const pool = new Pool(poolConfig);

/**
 * Test database connection
 */
export async function testConnection(): Promise<boolean> {
  try {
    const client = await pool.connect();
    await client.query('SELECT NOW()');
    client.release();
    return true;
  } catch (error) {
    console.error('Database connection failed:', error);
    return false;
  }
}

/**
 * Close database connection pool
 */
export async function closePool(): Promise<void> {
  await pool.end();
}
