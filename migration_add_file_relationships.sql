-- Migration: Add parent-child file relationships and screenshot support to STL files
-- Date: 2025-10-01
-- Description: Adds support for associating partial STL files with their full parent files and screenshot previews

-- Add new columns
ALTER TABLE stl_files ADD COLUMN parent_file_id VARCHAR(36);
ALTER TABLE stl_files ADD COLUMN is_partial BOOLEAN DEFAULT FALSE;
ALTER TABLE stl_files ADD COLUMN screenshot_s3_key VARCHAR(255);

-- For SQLite, foreign key constraints are checked at runtime if enabled
-- If you migrate to PostgreSQL/MySQL later, add this constraint:
-- ALTER TABLE stl_files ADD CONSTRAINT fk_parent_file FOREIGN KEY (parent_file_id) REFERENCES stl_files(id);

-- Enable foreign key support for SQLite (if not already enabled)
PRAGMA foreign_keys = ON;