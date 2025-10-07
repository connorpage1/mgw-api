#!/usr/bin/env python3
"""
Utility script to calculate file hashes for existing STL files
that don't have a file_hash value yet.
"""

import hashlib
import os
from app import create_app
from models import db, STLFile

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of file content"""
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except FileNotFoundError:
        print(f"Warning: File not found: {file_path}")
        return None
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

def main():
    """Calculate hashes for existing files without file_hash"""
    app = create_app()
    
    with app.app_context():
        # Find files without hash
        files_without_hash = STLFile.query.filter(
            (STLFile.file_hash.is_(None)) | (STLFile.file_hash == '')
        ).all()
        
        print(f"Found {len(files_without_hash)} files without hash")
        
        updated_count = 0
        error_count = 0
        
        for stl_file in files_without_hash:
            print(f"Processing: {stl_file.original_filename}")
            
            if stl_file.local_path and os.path.exists(stl_file.local_path):
                file_hash = calculate_file_hash(stl_file.local_path)
                if file_hash:
                    stl_file.file_hash = file_hash
                    updated_count += 1
                    print(f"  ✓ Hash calculated: {file_hash[:16]}...")
                else:
                    error_count += 1
                    print(f"  ✗ Failed to calculate hash")
            else:
                error_count += 1
                print(f"  ✗ File not found: {stl_file.local_path}")
        
        if updated_count > 0:
            try:
                db.session.commit()
                print(f"\n✓ Successfully updated {updated_count} files")
            except Exception as e:
                db.session.rollback()
                print(f"\n✗ Error saving to database: {e}")
        
        if error_count > 0:
            print(f"⚠ {error_count} files had errors")
        
        print("Done!")

if __name__ == '__main__':
    main()