-- Add first_name and last_name columns to users table
-- Migration: Add user name fields

ALTER TABLE users ADD COLUMN first_name VARCHAR(100);
ALTER TABLE users ADD COLUMN last_name VARCHAR(100);

-- Optional: Update existing admin user with a default first name
-- UPDATE users SET first_name = 'Admin' WHERE email LIKE '%admin%' OR email LIKE '%dev.local%';