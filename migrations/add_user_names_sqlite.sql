-- SQLite version: Add first_name and last_name columns to users table
-- Migration: Add user name fields

ALTER TABLE users ADD COLUMN first_name TEXT;
ALTER TABLE users ADD COLUMN last_name TEXT;

-- Optional: Update existing admin user with a default first name
-- UPDATE users SET first_name = 'Admin' WHERE email LIKE '%admin%' OR email LIKE '%dev.local%';