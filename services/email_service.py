"""
Email service for sending notifications with SendGrid and SMTP fallback support
"""
import os
import base64
from typing import List, Dict, Optional, Union
from dataclasses import dataclass
from flask import current_app
from utils.logger import logger

# Try to import SendGrid (optional dependency)
try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import (
        Mail,
        Content,
        Attachment,
        FileContent,
        FileName,
        FileType,
        Disposition,
    )
    SENDGRID_AVAILABLE = True
except ImportError:
    SENDGRID_AVAILABLE = False
    SendGridAPIClient = None
    Mail = None
    Content = None

# SMTP fallback imports
import smtplib
import email.mime.text
import email.mime.multipart
import email.mime.base
import email.encoders

@dataclass
class EmailAttachment:
    """Email attachment data class"""
    filename: str
    content: Union[bytes, str]
    content_type: str = 'application/octet-stream'
    disposition: str = 'attachment'

class EmailService:
    """Service for sending emails via SendGrid API or SMTP fallback"""
    
    def __init__(self):
        # Email provider configuration
        self.provider = os.environ.get('EMAIL_PROVIDER', '').lower()
        
        # SendGrid configuration
        self.sendgrid_api_key = os.environ.get('SENDGRID_API_KEY')
        self.sendgrid_from_email = os.environ.get('SENDGRID_FROM_EMAIL', os.environ.get('FROM_EMAIL'))
        self.sendgrid_from_name = os.environ.get('SENDGRID_FROM_NAME', os.environ.get('FROM_NAME', 'Mardi Gras World'))
        
        # SMTP fallback configuration
        self.smtp_server = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.environ.get('MAIL_PORT', '587'))
        self.smtp_username = os.environ.get('MAIL_USERNAME')
        self.smtp_password = os.environ.get('MAIL_PASSWORD')
        self.smtp_use_tls = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
        self.from_email = os.environ.get('FROM_EMAIL', 'noreply@mardigrasworld.com')
        self.from_name = os.environ.get('FROM_NAME', 'Mardi Gras World')
        
        # Initialize SendGrid client if available and configured
        self.sendgrid_client = None
        if SENDGRID_AVAILABLE and self.sendgrid_api_key and self.provider == 'sendgrid':
            try:
                self.sendgrid_client = SendGridAPIClient(api_key=self.sendgrid_api_key)
                logger.info("SendGrid client initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize SendGrid client: {e}")
                
    def send_email(self, 
                   recipients: List[str], 
                   subject: str, 
                   text_content: Optional[str] = None,
                   html_content: Optional[str] = None,
                   attachments: Optional[List[EmailAttachment]] = None) -> Dict[str, any]:
        """
        Send email via SendGrid API or SMTP fallback
        
        Args:
            recipients: List of recipient email addresses
            subject: Email subject
            text_content: Plain text content (optional)
            html_content: HTML content (optional) 
            attachments: List of EmailAttachment objects (optional)
            
        Returns:
            Dict with success status and details
        """
        if not recipients:
            return {'success': False, 'error': 'No recipients specified'}
            
        if not (text_content or html_content):
            return {'success': False, 'error': 'Either text_content or html_content must be provided'}
        
        # Try SendGrid first if configured
        if self.sendgrid_client:
            return self._send_via_sendgrid(recipients, subject, text_content, html_content, attachments)
        
        # Fallback to SMTP
        return self._send_via_smtp(recipients, subject, text_content, html_content, attachments)
    
    def _send_via_sendgrid(self, recipients: List[str], subject: str, text_content: Optional[str],
                          html_content: Optional[str], attachments: Optional[List[EmailAttachment]]) -> Dict[str, any]:
        """Send email via SendGrid API"""
        if not self.sendgrid_from_email:
            return {
                'success': False,
                'provider': 'sendgrid',
                'error': 'SENDGRID_FROM_EMAIL (or FROM_EMAIL) is not configured',
            }
        try:
            # Create SendGrid mail object
            message = Mail(
                from_email=(self.sendgrid_from_email, self.sendgrid_from_name),
                to_emails=recipients,
                subject=subject
            )

            # Add content — SendGrid requires text/plain before text/html
            if text_content:
                message.add_content(Content("text/plain", text_content))
            if html_content:
                message.add_content(Content("text/html", html_content))

            # Add attachments if provided
            if attachments:
                for attachment in attachments:
                    try:
                        # Convert content to base64 if it's bytes
                        if isinstance(attachment.content, bytes):
                            content_b64 = base64.b64encode(attachment.content).decode()
                        else:
                            content_b64 = base64.b64encode(attachment.content.encode()).decode()

                        sg_attachment = Attachment(
                            file_content=FileContent(content_b64),
                            file_name=FileName(attachment.filename),
                            file_type=FileType(attachment.content_type),
                            disposition=Disposition(attachment.disposition)
                        )
                        message.add_attachment(sg_attachment)

                    except Exception as e:
                        logger.warning(f"Failed to add attachment {attachment.filename}: {e}")
            
            # Send email
            response = self.sendgrid_client.send(message)
            
            if response.status_code in [200, 202]:
                logger.info(f"Email sent successfully via SendGrid to {recipients}")
                return {
                    'success': True, 
                    'provider': 'sendgrid',
                    'status_code': response.status_code,
                    'message_id': response.headers.get('X-Message-Id')
                }
            else:
                logger.error(f"SendGrid API error: {response.status_code} - {response.body}")
                return {
                    'success': False, 
                    'provider': 'sendgrid',
                    'error': f"API error: {response.status_code}",
                    'details': response.body
                }
                
        except Exception as e:
            logger.error(f"SendGrid email send failed: {e}")
            return {'success': False, 'provider': 'sendgrid', 'error': str(e)}
    
    def _send_via_smtp(self, recipients: List[str], subject: str, text_content: Optional[str],
                      html_content: Optional[str], attachments: Optional[List[EmailAttachment]]) -> Dict[str, any]:
        """Send email via SMTP"""
        try:
            # Create message
            msg = email.mime.multipart.MIMEMultipart('mixed')
            msg['Subject'] = subject
            msg['From'] = f"{self.from_name} <{self.from_email}>"
            msg['To'] = ', '.join(recipients)
            
            # Create content container
            content_container = email.mime.multipart.MIMEMultipart('alternative')
            
            # Add text content
            if text_content:
                text_part = email.mime.text.MIMEText(text_content, 'plain')
                content_container.attach(text_part)
            
            # Add HTML content
            if html_content:
                html_part = email.mime.text.MIMEText(html_content, 'html')
                content_container.attach(html_part)
            
            msg.attach(content_container)
            
            # Add attachments if provided
            if attachments:
                for attachment in attachments:
                    try:
                        part = email.mime.base.MIMEBase('application', 'octet-stream')
                        
                        if isinstance(attachment.content, bytes):
                            part.set_payload(attachment.content)
                        else:
                            part.set_payload(attachment.content.encode())
                        
                        email.encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            f'{attachment.disposition}; filename= {attachment.filename}'
                        )
                        part.add_header('Content-Type', attachment.content_type)
                        msg.attach(part)
                        
                    except Exception as e:
                        logger.warning(f"Failed to add SMTP attachment {attachment.filename}: {e}")
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.smtp_use_tls:
                    server.starttls()
                if self.smtp_username and self.smtp_password:
                    server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg, to_addrs=recipients)
            
            logger.info(f"Email sent successfully via SMTP to {recipients}")
            return {'success': True, 'provider': 'smtp'}
            
        except Exception as e:
            logger.error(f"SMTP email send failed: {e}")
            return {'success': False, 'provider': 'smtp', 'error': str(e)}

    # Legacy compatibility methods
    def _send_email(self, to_email: str, subject: str, html_content: str, text_content: str = None) -> bool:
        """Legacy method for backward compatibility"""
        result = self.send_email([to_email], subject, text_content, html_content)
        return result.get('success', False)

# Create a global instance
email_service = EmailService()