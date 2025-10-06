"""
Logging configuration and utilities
"""
import logging
import os

# Configure logging
log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Application logger
logger = logging.getLogger('mardi-gras-api')