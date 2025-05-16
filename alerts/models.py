from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models import Count, Q
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.db.models.signals import post_save
from django.dispatch import receiver
import logging
import requests
import json
import time

logger = logging.getLogger(__name__)

class Alert(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    STATUS_CHOICES = [
        ('new', 'New'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('ignored', 'Ignored'),
    ]
    
    TYPE_CHOICES = [
        ('intrusion', 'Intrusion Attempt'),
        ('malware', 'Malware Detection'),
        ('authentication', 'Authentication Failure'),
        ('anomaly', 'Anomalous Activity'),
        ('policy', 'Policy Violation'),
    ]
    
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    type = models.CharField(max_length=50, choices=TYPE_CHOICES, db_index=True)
    source = models.CharField(max_length=100, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new', db_index=True)
    description = models.TextField()
    ip_address = models.CharField(max_length=50, blank=True, null=True, db_index=True)
    user = models.CharField(max_length=100, blank=True, null=True)
    affected_systems = models.TextField(blank=True, null=True)
    mitre_tactics = models.TextField(blank=True, null=True)
    recommendation = models.TextField(blank=True, null=True)
    
    # Fields for real-time tracking
    raw_log_id = models.IntegerField(blank=True, null=True, help_text="Reference to original raw log")
    parsed_log_id = models.IntegerField(blank=True, null=True, help_text="Reference to parsed log")
    detection_time = models.FloatField(blank=True, null=True, help_text="Time taken to detect the alert in ms")
    
    # Analysis fields
    analysis_data = models.JSONField(blank=True, null=True, help_text="Additional analysis data")
    is_analyzed = models.BooleanField(default=False, help_text="Whether this alert has been analyzed")
    last_analyzed = models.DateTimeField(null=True, blank=True, help_text="When the alert was last analyzed")
    
    # Additional relationship fields
    related_alerts = models.ManyToManyField('self', blank=True, symmetrical=False, related_name='related_to')
    
    class Meta:
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['severity']),
            models.Index(fields=['status']),
            models.Index(fields=['type']),
            models.Index(fields=['ip_address']),
        ]
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"Alert {self.id}: {self.type} ({self.severity})"
    
    def mark_as_analyzed(self, analysis_data=None):
        """Mark this alert as analyzed with optional analysis data"""
        self.is_analyzed = True
        self.last_analyzed = timezone.now()
        if analysis_data:
            self.analysis_data = analysis_data
        self.save(update_fields=['is_analyzed', 'last_analyzed', 'analysis_data'])
    
    def add_related_alert(self, alert):
        """Associate this alert with another related alert"""
        self.related_alerts.add(alert)
    
    @staticmethod
    def get_counts_by_severity(status_filter=None):
        """Get count of alerts by severity"""
        query = Alert.objects
        if status_filter:
            query = query.filter(status__in=status_filter)
            
        return {
            severity.lower(): count 
            for severity, count in query.values('severity')
                                    .annotate(count=Count('id'))
                                    .values_list('severity', 'count')
        }
    
    @staticmethod
    def get_active_alerts():
        """Get alerts that are not resolved or ignored"""
        return Alert.objects.exclude(status__in=['resolved', 'ignored'])

class AlertNote(models.Model):
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='notes')
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['alert']),
        ]
    
    def __str__(self):
        return f"Note on Alert {self.alert.id} by {self.created_by}"

# SMTP Integration Models (moved from smtp_integration)
class SMTPConfiguration(models.Model):
    """Model to store SMTP server settings"""
    host = models.CharField(max_length=255, default='smtp.gmail.com')
    port = models.IntegerField(default=587)
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    use_tls = models.BooleanField(default=True)
    use_ssl = models.BooleanField(default=False)
    default_from_email = models.EmailField(default='alerts@loganalyzer.com')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"SMTP Config: {self.host}:{self.port}"

    @classmethod
    def get_active_config(cls):
        """Get the active SMTP configuration"""
        try:
            return cls.objects.filter(is_active=True).first()
        except Exception as e:
            logger.error(f"Error retrieving SMTP config: {e}")
            return None

class EmailAlert(models.Model):
    """Model to track email alerts sent"""
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    subject = models.CharField(max_length=255)
    message = models.TextField()
    recipient = models.EmailField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    related_alert_id = models.IntegerField(null=True, blank=True)
    status = models.CharField(max_length=20, default='pending')  # pending, sent, failed
    error_message = models.TextField(blank=True, null=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Email Alert: {self.subject} ({self.status})"

# Notification Preferences and In-App Notifications
class NotificationPreference(models.Model):
    """Model to store user notification preferences"""
    # Severity levels for comparison
    SEVERITY_LEVELS = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
    }
    
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    
    # Email preferences
    email_alerts = models.BooleanField(default=True)
    email_threshold = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='high')
    
    # Push notification preferences
    push_alerts = models.BooleanField(default=True)
    push_threshold = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='high')
    
    # In-app notification preferences
    in_app_alerts = models.BooleanField(default=True)
    in_app_threshold = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Notification Preferences for {self.user.username}"
    
    @classmethod
    def get_severity_level(cls, severity):
        """Get the numeric level for a severity string"""
        if not severity:
            return 1
        sev_lower = severity.lower()
        return cls.SEVERITY_LEVELS.get(sev_lower, 1)

class AlertNotification(models.Model):
    """Model to store in-app notifications"""
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    message = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    threat_id = models.IntegerField(null=True, blank=True)
    source_ip = models.CharField(max_length=45, blank=True, null=True)
    affected_system = models.CharField(max_length=100, blank=True, null=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Alert: {self.title} for {self.user.username}"

# Create default notification preferences when a user is created
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_notification_preferences(sender, instance, created, **kwargs):
    if created:
        NotificationPreference.objects.create(user=instance)

class NotificationEvent(models.Model):
    """Track notification events for analytics purposes"""
    EVENT_TYPES = [
        ('sent', 'Sent'),
        ('delivered', 'Delivered'),
        ('opened', 'Opened'),
        ('clicked', 'Clicked'),
        ('failed', 'Failed'),
    ]
    
    NOTIFICATION_TYPES = [
        ('email', 'Email'),
        ('in_app', 'In-App'),
        ('push', 'Push Notification'),
        ('sms', 'SMS'),
        ('slack', 'Slack'),
    ]
    
    event_type = models.CharField(max_length=20, choices=EVENT_TYPES)
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    alert_id = models.IntegerField(null=True, blank=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.JSONField(null=True, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['notification_type']),
            models.Index(fields=['event_type']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['user']),
        ]

class EmailNotifier:
    """Service class to handle sending email notifications"""
    
    # HTML email template stored as class variable to avoid creating separate files
    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>{{ subject }}</title>
        <style>
            body {
                font-family: 'Segoe UI', Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 0;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 600px;
                margin: 20px auto;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                background-color: #fff;
            }
            .header {
                background-color: #{{ color }};
                color: white;
                padding: 20px 25px;
                border-radius: 5px 5px 0 0;
            }
            .header h1 {
                margin: 0;
                font-size: 24px;
                font-weight: 600;
            }
            .content {
                background-color: #ffffff;
                padding: 25px;
                border: 1px solid #ddd;
                border-top: none;
            }
            .alert-badge {
                display: inline-block;
                padding: 6px 12px;
                background-color: #{{ color }};
                color: white;
                border-radius: 4px;
                font-weight: bold;
                margin-bottom: 15px;
                font-size: 14px;
                letter-spacing: 0.5px;
            }
            .alert-info {
                background-color: #f8f9fa;
                border-left: 4px solid #{{ color }};
                padding: 12px 15px;
                margin: 15px 0;
                border-radius: 0 4px 4px 0;
            }
            .action-btn {
                display: inline-block;
                background-color: #3f51b5;
                color: white;
                text-decoration: none;
                padding: 12px 24px;
                border-radius: 4px;
                margin-top: 20px;
                font-weight: 600;
                text-align: center;
                transition: background-color 0.3s;
            }
            .action-btn:hover {
                background-color: #303f9f;
            }
            .footer {
                margin-top: 25px;
                padding-top: 15px;
                font-size: 13px;
                color: #777;
                text-align: center;
                border-top: 1px solid #eee;
            }
            .timestamp {
                background-color: #f8f9fa;
                padding: 8px;
                border-radius: 4px;
                font-size: 12px;
                text-align: center;
                margin-top: 10px;
                color: #666;
            }
            .meta-info {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 10px;
                margin: 15px 0;
            }
            .meta-item {
                padding: 8px 12px;
                background-color: #f8f9fa;
                border-radius: 4px;
            }
            .meta-item strong {
                display: block;
                font-size: 13px;
                color: #555;
            }
            .meta-item span {
                font-size: 15px;
                word-break: break-word;
            }
            .cta-container {
                text-align: center;
                margin: 25px 0 15px;
            }
            .message-content {
                line-height: 1.7;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>{{ title }}</h1>
            </div>
            <div class="content">
                <div class="alert-badge">{{ severity }}</div>
                
                <div class="message-content">{{ message|linebreaks }}</div>
                
                <div class="meta-info">
                    {% if source_ip %}
                    <div class="meta-item">
                        <strong>Source IP:</strong>
                        <span>{{ source_ip }}</span>
                    </div>
                    {% endif %}
                    
                    {% if affected_system %}
                    <div class="meta-item">
                        <strong>Affected System:</strong>
                        <span>{{ affected_system }}</span>
                    </div>
                    {% endif %}
                    
                    {% if mitre_tactics %}
                    <div class="meta-item">
                        <strong>MITRE Tactics:</strong>
                        <span>{{ mitre_tactics }}</span>
                    </div>
                    {% endif %}
                    
                    {% if detection_time %}
                    <div class="meta-item">
                        <strong>Detection Time:</strong>
                        <span>{{ detection_time }} ms</span>
                    </div>
                    {% endif %}
                </div>
                
                <div class="alert-info">
                    <p>Please take appropriate action based on the severity of this alert.</p>
                </div>
                
                <div class="cta-container">
                    {% if alert_id %}
                    <a href="{{ base_url }}/alerts/{{ alert_id }}/" class="action-btn" style="display: inline-block; background-color: #3f51b5; color: #FFFFFF !important; text-decoration: none; padding: 12px 24px; border-radius: 4px; margin-top: 20px; font-weight: 600; text-align: center; font-family: Arial, sans-serif; font-size: 16px; line-height: 1.5;">
                        <span style="color: #FFFFFF !important; text-decoration: none; display: inline-block;">View Alert Details</span>
                    </a>
                    {% endif %}
                </div>
            </div>
            <div class="footer">
                <p>This is an automated security alert from your Log Detection Platform.</p>
                <div class="timestamp">Time of detection: {{ timestamp }}</div>
            </div>
        </div>
    </body>
    </html>
    """

    WELCOME_EMAIL_TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Welcome to LogSentry</title>
        <style>
            body {
                font-family: 'Segoe UI', Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 0;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 600px;
                margin: 20px auto;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                background-color: #fff;
            }
            .header {
                background-color: #3f51b5;
                color: white;
                padding: 20px 25px;
                border-radius: 5px 5px 0 0;
            }
            .header h1 {
                margin: 0;
                font-size: 24px;
                font-weight: 600;
            }
            .content {
                background-color: #ffffff;
                padding: 25px;
                border: 1px solid #ddd;
                border-top: none;
            }
            .welcome-message {
                font-size: 16px;
                line-height: 1.5;
                margin-bottom: 20px;
            }
            .credentials-box {
                background-color: #f8f9fa;
                border-left: 4px solid #3f51b5;
                padding: 15px;
                margin: 15px 0;
                border-radius: 0 4px 4px 0;
            }
            .credentials-box p {
                margin: 8px 0;
            }
            .credentials-label {
                font-weight: bold;
                color: #333;
            }
            .action-btn {
                display: inline-block;
                background-color: #3f51b5;
                color: #FFFFFF !important;
                text-decoration: none;
                padding: 12px 24px;
                border-radius: 4px;
                margin-top: 20px;
                font-weight: 600;
                text-align: center;
            }
            .action-btn:hover {
                background-color: #303f9f;
            }
            .footer {
                margin-top: 25px;
                padding-top: 15px;
                font-size: 13px;
                color: #777;
                text-align: center;
                border-top: 1px solid #eee;
            }
            .security-note {
                background-color: #fff8e1;
                border-left: 4px solid #ffc107;
                padding: 10px 15px;
                margin: 15px 0;
                font-size: 13px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Welcome to LogSentry</h1>
            </div>
            <div class="content">
                <div class="welcome-message">
                    <p>Hello {{ first_name }} {{ last_name }},</p>
                    <p>Your account has been successfully created on the LogSentry platform. We're excited to have you on board!</p>
                </div>
                
                <p>You can now log in using the following credentials:</p>
                
                <div class="credentials-box">
                    <p><span class="credentials-label">Username:</span> {{ username }}</p>
                    <p><span class="credentials-label">Password:</span> {{ password }}</p>
                    <p><span class="credentials-label">Role:</span> {{ role }}</p>
                </div>
                
                <div class="security-note">
                    <strong>Security Note:</strong> We recommend changing your password after your first login.
                </div>
                
                <a href="{{ base_url }}/login/" class="action-btn">
                    Login to Your Account
                </a>
                
                <p style="margin-top: 20px;">If you have any questions or need assistance, please contact your administrator.</p>
            </div>
            <div class="footer">
                <p>This is an automated message from LogSentry. Please do not reply to this email.</p>
                <p>© {% now "Y" %} LogSentry. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    """

    @classmethod
    def send_alert(cls, subject, message, severity, recipients, alert_id=None, source_ip=None, affected_system=None, mitre_tactics=None, detection_time=None):
        """Send an email alert using Django's email system"""
        from django.core.mail import EmailMultiAlternatives
        from django.utils import timezone
        from django.conf import settings
        import logging
        
        logger = logging.getLogger(__name__)
        
        try:
            # Determine color based on severity
            severity_colors = {
                'critical': 'dc3545',
                'high': 'fd7e14',
                'medium': '17a2b8',
                'low': '28a745'
            }
            color = severity_colors.get(severity.lower(), '17a2b8')
            
            # Prepare context for HTML template
            context = {
                'title': subject,
                'message': message,
                'severity': severity.upper(),
                'color': color,
                'source_ip': source_ip,
                'affected_system': affected_system,
                'mitre_tactics': mitre_tactics,
                'detection_time': detection_time,
                'alert_id': alert_id,
                'base_url': settings.SITE_URL if hasattr(settings, 'SITE_URL') else 'http://localhost:8000',
                'timestamp': timezone.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Render HTML content using template
            from django.template import Template, Context
            template = Template(cls.HTML_TEMPLATE)
            html_content = template.render(Context(context))
            
            # Create plain text version
            text_content = f"""
SECURITY ALERT: {subject}

Severity: {severity.upper()}

{message}

{f"Source IP: {source_ip}" if source_ip else ""}
{f"Affected System: {affected_system}" if affected_system else ""}
{f"MITRE Tactics: {mitre_tactics}" if mitre_tactics else ""}

{f"Alert ID: {alert_id}" if alert_id else ""}
{f"View Alert Details: {settings.SITE_URL}/alerts/{alert_id}/" if alert_id and hasattr(settings, 'SITE_URL') else ""}

This is an automated security alert.
            """
            
            # Create email
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=recipients
            )
            
            # Attach HTML alternative
            email.attach_alternative(html_content, "text/html")
            
            # Send email
            email.send()
            
            logger.info(f"Email alert sent to {', '.join(recipients)}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False

    @classmethod
    def send_welcome_email(cls, recipient, username, password, first_name='', last_name='', role='Regular User'):
        """Send a welcome email with login credentials to a new user"""
        from django.template import Template, Context
        from django.utils import timezone
        from django.conf import settings
        from django.core.mail import EmailMultiAlternatives
        import logging
        
        logger = logging.getLogger(__name__)
        
        try:
            # Prepare context for HTML template
            context = {
                'first_name': first_name,
                'last_name': last_name,
                'username': username,
                'password': password,
                'role': role,
                'base_url': settings.SITE_URL if hasattr(settings, 'SITE_URL') else 'http://localhost:8000',
                'timestamp': timezone.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Render HTML content using template
            template = Template(cls.WELCOME_EMAIL_TEMPLATE)
            html_content = template.render(Context(context))
            
            # Create plain text version
            text_content = f"""
Welcome to LogSentry!

Hello {first_name} {last_name},

Your account has been successfully created on the LogSentry platform. We're excited to have you on board!

You can now log in using the following credentials:
- Username: {username}
- Password: {password}
- Role: {role}

Security Note: We recommend changing your password after your first login.

Login to your account at: {settings.SITE_URL if hasattr(settings, 'SITE_URL') else 'http://localhost:8000'}/login/

If you have any questions or need assistance, please contact your administrator.

This is an automated message from LogSentry. Please do not reply to this email.
            """
            
            # Create email
            subject = "Welcome to LogSentry - Your Account Details"
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[recipient]
            )
            
            # Attach HTML alternative
            email.attach_alternative(html_content, "text/html")
            
            # Send email
            email.send()
            
            logger.info(f"Welcome email sent to {recipient}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send welcome email: {e}")
            return False

class PushNotificationService:
    """Service to handle push notifications using Firebase Cloud Messaging"""
    
    def send_notification(self, device_tokens, title, message, data=None):
        """Send push notification to device token(s)"""
        if not device_tokens:
            logger.warning("No device tokens provided for push notification")
            return False
            
        if not settings.FCM_API_KEY:
            logger.error("FCM API key not configured")
            return False
            
        headers = {
            'Authorization': f'key={settings.FCM_API_KEY}',
            'Content-Type': 'application/json'
        }
        
        # Ensure data is a dict
        if data is None:
            data = {}
            
        # Construct notification payload
        payload = {
            'notification': {
                'title': title,
                'body': message,
                'click_action': settings.SITE_URL,
                'icon': '/static/images/notification-icon.png'
            },
            'data': data
        }
        
        success_count = 0
        # Send to each token individually to handle failures better
        for token in device_tokens:
            try:
                payload['to'] = token
                
                # Send request to FCM
                response = requests.post(
                    'https://fcm.googleapis.com/fcm/send',
                    headers=headers,
                    data=json.dumps(payload)
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('success', 0) == 1:
                        success_count += 1
                    else:
                        logger.warning(f"FCM rejected notification: {result}")
                else:
                    logger.error(f"FCM API error: {response.status_code}, {response.text}")
            except Exception as e:
                logger.error(f"Error sending push notification: {e}")
        
        return success_count > 0

class SlackNotifier:
    """Service class to handle sending Slack notifications"""
    
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url or settings.SLACK_WEBHOOK_URL
        
    def send_alert(self, alert):
        """Send alert notification to Slack channel"""
        color_map = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#17a2b8'
        }
        
        payload = {
            'attachments': [{
                'fallback': f"[{alert.severity.upper()}] {alert.title}",
                'color': color_map.get(alert.severity, '#6c757d'),
                'title': f"[{alert.severity.upper()}] {alert.title}",
                'title_link': f"{settings.SITE_URL}/alert-detail/{alert.id}/",
                'text': alert.description,
                'fields': [
                    {
                        'title': 'Severity',
                        'value': alert.severity.capitalize(),
                        'short': True
                    },
                    {
                        'title': 'Source IP',
                        'value': alert.source_ip or 'N/A',
                        'short': True
                    }
                ],
                'footer': 'Threat Detection Platform',
                'ts': int(time.time())
            }]
        }
        
        response = requests.post(
            self.webhook_url,
            data=json.dumps(payload),
            headers={'Content-Type': 'application/json'}
        )
        
        return response.status_code == 200
