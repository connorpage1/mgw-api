"""
Email service for sending user notifications and password setup links
"""
import smtplib
import os
import secrets
import hashlib
from datetime import datetime, timedelta
from flask import current_app, render_template, url_for
from models import db, User, PasswordResetToken
from utils.logger import logger

# Import email classes with explicit module references to avoid conflicts
import email.mime.text
import email.mime.multipart


class EmailService:
    """Service for sending emails"""
    
    def __init__(self):
        self.smtp_server = os.environ.get('SMTP_SERVER', 'localhost')
        self.smtp_port = int(os.environ.get('SMTP_PORT', '587'))
        self.smtp_username = os.environ.get('SMTP_USERNAME')
        self.smtp_password = os.environ.get('SMTP_PASSWORD')
        self.smtp_use_tls = os.environ.get('SMTP_USE_TLS', 'true').lower() == 'true'
        self.from_email = os.environ.get('FROM_EMAIL', 'noreply@mardigrasworld.com')
        
    def _send_email(self, to_email, subject, html_content, text_content=None):
        """Send an email via SMTP"""
        try:
            # Create message
            msg = email.mime.multipart.MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = to_email
            
            # Add text version if provided
            if text_content:
                part1 = email.mime.text.MIMEText(text_content, 'plain')
                msg.attach(part1)
            
            # Add HTML version
            part2 = email.mime.text.MIMEText(html_content, 'html')
            msg.attach(part2)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls()
                if self.smtp_username and self.smtp_password:
                    server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False
    
    def generate_password_setup_token(self, user_id):
        """Generate a secure password setup token"""
        # Generate a random token
        raw_token = secrets.token_urlsafe(32)
        
        # Hash the token for storage
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        # Set expiration (24 hours from now)
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        # Store in database
        reset_token = PasswordResetToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at
        )
        
        db.session.add(reset_token)
        db.session.commit()
        
        return raw_token
    
    def send_welcome_email(self, user):
        """Send welcome email with password setup link"""
        try:
            # Generate password setup token
            token = self.generate_password_setup_token(user.id)
            
            # Generate password setup URL
            set_password_url = url_for('auth.set_password', token=token, _external=True)
            
            # Render email template
            html_content = render_template('email/welcome_set_password.html', 
                                         user=user, 
                                         set_password_url=set_password_url)
            
            # Send email
            subject = "Welcome to Mardi Gras Admin - Set Your Password"
            return self._send_email(user.email, subject, html_content)
            
        except Exception as e:
            logger.error(f"Failed to send welcome email to {user.email}: {e}")
            return False
    
    def send_password_reset_email(self, user):
        """Send password reset email"""
        try:
            # Generate password reset token
            token = self.generate_password_setup_token(user.id)
            
            # Generate password reset URL
            reset_url = url_for('auth.set_password', token=token, _external=True)
            
            # Render email template
            html_content = render_template('email/password_reset.html', 
                                         user=user, 
                                         reset_url=reset_url)
            
            # Send email
            subject = "Password Reset Request - Mardi Gras Admin"
            return self._send_email(user.email, subject, html_content)
            
        except Exception as e:
            logger.error(f"Failed to send password reset email to {user.email}: {e}")
            return False


# Create a global instance
email_service = EmailService()