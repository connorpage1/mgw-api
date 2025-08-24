-- Migration: Remove is_admin column from users table (SQLite compatible)
PRAGMA foreign_keys=off;

BEGIN TRANSACTION;

-- 1. Create a new table without is_admin
CREATE TABLE users_new AS SELECT id, email, username, password, active, current_login_at, current_login_ip, last_login_at, last_login_ip, login_count, api_key, created_at FROM users;

-- 2. Drop the old users table
DROP TABLE users;

-- 3. Rename the new table to users
ALTER TABLE users_new RENAME TO users;

COMMIT;

PRAGMA foreign_keys=on;
