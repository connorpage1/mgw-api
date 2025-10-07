-- Migration to add file_hash column to stl_files table
-- This supports duplicate file detection by content hash

-- Add file_hash column to stl_files table
ALTER TABLE stl_files ADD COLUMN file_hash VARCHAR(64);

-- Add index on file_hash for faster duplicate lookups
CREATE INDEX idx_stl_files_file_hash ON stl_files(file_hash);

-- Add composite index on filename and file_size for faster duplicate lookups
CREATE INDEX idx_stl_files_name_size ON stl_files(original_filename, file_size);

-- Note: Existing files will have NULL file_hash until they are re-uploaded or processed
-- You may want to run a script to calculate hashes for existing files