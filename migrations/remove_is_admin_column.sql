-- Migration: Remove is_admin column from users table
ALTER TABLE users DROP COLUMN IF EXISTS is_admin;
