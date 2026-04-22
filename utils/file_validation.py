"""
File validation utilities for secure file uploads
"""

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    magic = None

from typing import Dict, List, Optional

class FileValidator:
    """Secure file validation using magic numbers and file signatures"""
    
    # Allowed MIME types for different file categories
    ALLOWED_MIMES = {
        'stl': ['application/octet-stream', 'model/stl', 'text/plain'],
        'video': [
            'video/mp4',
            'video/quicktime',
            'video/x-msvideo',
            'video/x-matroska',
            'video/webm'
        ]
    }
    
    # File signatures (magic numbers) for validation
    FILE_SIGNATURES = {
        # STL files typically start with "solid " for ASCII or have binary headers
        'stl_ascii': b'solid ',
        'stl_binary_start': b'\x00\x00\x00\x00',  # Some STL files start with null bytes
        
        # Video file signatures
        'mp4': [b'\x00\x00\x00\x18ftypmp4', b'\x00\x00\x00\x20ftypmp4'],
        'mov': [b'\x00\x00\x00\x14ftypqt  '],
        'avi': [b'RIFF', b'AVI '],
        'mkv': [b'\x1a\x45\xdf\xa3'],
        'webm': [b'\x1a\x45\xdf\xa3']
    }
    
    @staticmethod
    def validate_file_type(file_path: str, expected_type: str, filename: str) -> Dict[str, any]:
        """
        Validate file type using multiple methods:
        1. MIME type detection
        2. File signature validation
        3. Extension validation
        """
        try:
            # Initialize python-magic (fallback gracefully if not available)
            if MAGIC_AVAILABLE:
                try:
                    mime_type = magic.from_file(file_path, mime=True)
                except Exception:
                    mime_type = None
            else:
                mime_type = None
                
            # Read first 32 bytes for signature validation
            with open(file_path, 'rb') as f:
                file_header = f.read(32)
            
            # Validate based on expected type
            if expected_type == 'stl':
                return FileValidator._validate_stl_file(
                    file_path, mime_type, file_header, filename
                )
            elif expected_type == 'video':
                return FileValidator._validate_video_file(
                    file_path, mime_type, file_header, filename
                )
            else:
                return {
                    'valid': False,
                    'error': f'Unsupported file type: {expected_type}'
                }
                
        except Exception as e:
            return {
                'valid': False,
                'error': f'File validation failed: {str(e)}'
            }
    
    @staticmethod
    def _validate_stl_file(file_path: str, mime_type: Optional[str], 
                          file_header: bytes, filename: str) -> Dict[str, any]:
        """Validate STL file format"""
        
        # Check extension
        if not filename.lower().endswith('.stl'):
            return {'valid': False, 'error': 'Invalid STL file extension'}
        
        # Check MIME type (if available)
        if mime_type and mime_type not in FileValidator.ALLOWED_MIMES['stl']:
            # Be lenient with MIME types as STL files can have various MIME types
            pass
            
        # Check file signatures
        is_ascii_stl = file_header.startswith(FileValidator.FILE_SIGNATURES['stl_ascii'])
        is_binary_stl = len(file_header) >= 80  # Binary STL files have 80-byte header
        
        if not (is_ascii_stl or is_binary_stl):
            return {'valid': False, 'error': 'Invalid STL file format'}
        
        return {
            'valid': True,
            'format': 'ascii' if is_ascii_stl else 'binary',
            'mime_type': mime_type
        }
    
    @staticmethod
    def _validate_video_file(file_path: str, mime_type: Optional[str],
                            file_header: bytes, filename: str) -> Dict[str, any]:
        """Validate video file format"""
        
        # Check extension
        valid_extensions = ['.mp4', '.mov', '.avi', '.mkv', '.webm']
        if not any(filename.lower().endswith(ext) for ext in valid_extensions):
            return {'valid': False, 'error': 'Invalid video file extension'}
        
        # Check MIME type (if available)
        if mime_type and mime_type not in FileValidator.ALLOWED_MIMES['video']:
            return {'valid': False, 'error': f'Invalid video MIME type: {mime_type}'}
        
        # Check file signatures for common video formats
        for format_name, signatures in FileValidator.FILE_SIGNATURES.items():
            if format_name in ['mp4', 'mov', 'avi', 'mkv', 'webm']:
                if isinstance(signatures, list):
                    for sig in signatures:
                        if file_header.startswith(sig) or sig in file_header[:20]:
                            return {
                                'valid': True,
                                'format': format_name,
                                'mime_type': mime_type
                            }
                else:
                    if file_header.startswith(signatures) or signatures in file_header[:20]:
                        return {
                            'valid': True,
                            'format': format_name,
                            'mime_type': mime_type
                        }
        
        # For video files, be more lenient if MIME type is correct
        if mime_type and mime_type in FileValidator.ALLOWED_MIMES['video']:
            return {
                'valid': True,
                'format': 'unknown',
                'mime_type': mime_type
            }
        
        return {'valid': False, 'error': 'Invalid video file format'}

    @staticmethod
    def validate_file_size(file_path: str, max_size_mb: int = 100) -> Dict[str, any]:
        """Validate file size"""
        try:
            import os
            file_size = os.path.getsize(file_path)
            max_size_bytes = max_size_mb * 1024 * 1024
            
            if file_size > max_size_bytes:
                return {
                    'valid': False,
                    'error': f'File too large: {file_size / (1024*1024):.1f}MB (max: {max_size_mb}MB)'
                }
            
            return {
                'valid': True,
                'size_bytes': file_size,
                'size_mb': file_size / (1024 * 1024)
            }
            
        except Exception as e:
            return {'valid': False, 'error': f'Size validation failed: {str(e)}'}