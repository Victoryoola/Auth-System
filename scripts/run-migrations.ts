import { pool } from '../src/config/database';
import fs from 'fs';
import path from 'path';

/**
 * Run database migrations in order
 */
async function runMigrations(): Promise<void> {
  const migrationsDir = path.join(__dirname, '..', 'migrations');
  const migrationFiles = fs
    .readdirSync(migrationsDir)
    .filter((file) => file.endsWith('.sql'))
    .sort();

  console.log('Starting database migrations...\n');

  for (const file of migrationFiles) {
    const filePath = path.join(migrationsDir, file);
    const sql = fs.readFileSync(filePath, 'utf-8');

    try {
      console.log(`Running migration: ${file}`);
      await pool.query(sql);
      console.log(`✓ ${file} completed successfully\n`);
    } catch (error) {
      console.error(`✗ ${file} failed:`, error);
      throw error;
    }
  }

  console.log('All migrations completed successfully!');
}

// Run migrations and exit
runMigrations()
  .then(() => {
    console.log('\nClosing database connection...');
    return pool.end();
  })
  .then(() => {
    console.log('Done!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\nMigration failed:', error);
    pool.end().then(() => process.exit(1));
  });
