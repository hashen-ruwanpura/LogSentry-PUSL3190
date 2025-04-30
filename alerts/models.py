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

class EmailNotifier:
    """Service class to handle sending email notifications"""
    
    # HTML email template stored as class variable to avoid creating separate files
    ALERT_EMAIL_TEMPLATE = '''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{ subject }}</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 0;
            }
            .container {
                width: 100%;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }
            .header {
                background-color: #f8f9fa;
                padding: 20px;
                text-align: center;
                border-bottom: 3px solid #3f51b5;
            }
            .content {
                padding: 20px;
            }
            .footer {
                background-color: #f8f9fa;
                padding: 20px;
                text-align: center;
                font-size: 12px;
                color: #6c757d;
            }
            .alert-critical {
                border-left: 4px solid #dc3545;
                background-color: #f8d7da;
                padding: 15px;
            }
            .alert-high {
                border-left: 4px solid #fd7e14;
                background-color: #fff3cd;
                padding: 15px;
            }
            .alert-medium {
                border-left: 4px solid #ffc107;
                background-color: #fff9e6;
                padding: 15px;
            }
            .alert-low {
                border-left: 4px solid #17a2b8;
                background-color: #d1ecf1;
                padding: 15px;
            }
            .btn {
                display: inline-block;
                background-color: #3f51b5;
                color: white;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 4px;
                margin-top: 15px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }
            table th, table td {
                padding: 8px;
                text-align: left;
                border-bottom: 1px solid #dee2e6;
            }
            table th {
                background-color: #f8f9fa;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Security Alert</h1>
            </div>
            <div class="content">
                <div class="alert-{{ severity }}">
                    <h2>{{ subject }}</h2>
                    <p>{{ message|linebreaks }}</p>
                    
                    {% if alert_details %}
                    <table>
                        <tr>
                            <th>Alert Severity</th>
                            <td>{{ severity|title }}</td>
                        </tr>
                        {% if source_ip %}
                        <tr>
                            <th>Source IP</th>
                            <td>{{ source_ip }}</td>
                        </tr>
                        {% endif %}
                        {% if affected_system %}
                        <tr>
                            <th>Affected System</th>
                            <td>{{ affected_system }}</td>
                        </tr>
                        {% endif %}
                        {% if timestamp %}
                        <tr>
                            <th>Detected At</th>
                            <td>{{ timestamp }}</td>
                        </tr>
                        {% endif %}
                    </table>
                    {% endif %}
                    
                    {% if alert_id %}
                    <a href="{{ base_url }}/alert-detail/{{ alert_id }}/" class="btn">View Alert Details</a>
                    {% endif %}
                </div>
            </div>
            <div class="footer">
                <p>This is an automated message from your Log Detection Platform.</p>
                <p>© {% now "Y" %} Log Detection Platform | Please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    '''
    
    INCIDENT_EMAIL_TEMPLATE = '''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{ subject }}</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 0;
            }
            .container {
                width: 100%;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
            }
            .header {
                background-color: #f8f9fa;
                padding: 20px;
                text-align: center;
                border-bottom: 3px solid #3f51b5;
            }
            .content {
                padding: 20px;
            }
            .footer {
                background-color: #f8f9fa;
                padding: 20px;
                text-align: center;
                font-size: 12px;
                color: #6c757d;
            }
            .incident-critical {
                border-left: 4px solid #dc3545;
                background-color: #f8d7da;
                padding: 15px;
            }
            .incident-high {
                border-left: 4px solid #fd7e14;
                background-color: #fff3cd;
                padding: 15px;
            }
            .incident-medium {
                border-left: 4px solid #ffc107;
                background-color: #fff9e6;
                padding: 15px;
            }
            .incident-low {
                border-left: 4px solid #17a2b8;
                background-color: #d1ecf1;
                padding: 15px;
            }
            .btn {
                display: inline-block;
                background-color: #3f51b5;
                color: white;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 4px;
                margin-top: 15px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }
            table th, table td {
                padding: 8px;
                text-align: left;
                border-bottom: 1px solid #dee2e6;
            }
            table th {
                background-color: #f8f9fa;
            }
            .related-alerts {
                margin-top: 15px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Security Incident</h1>
            </div>
            <div class="content">
                <div class="incident-{{ severity }}">
                    <h2>{{ subject }}</h2>
                    <p>{{ message|linebreaks }}</p>
                    
                    <table>
                        <tr>
                            <th>Incident ID</th>
                            <td>#{{ incident_id }}</td>
                        </tr>
                        <tr>
                            <th>Severity</th>
                            <td>{{ severity|title }}</td>
                        </tr>
                        <tr>
                            <th>Status</th>
                            <td>{{ status|title }}</td>
                        </tr>
                        <tr>
                            <th>Start Time</th>
                            <td>{{ start_time }}</td>
                        </tr>
                        {% if affected_systems %}
                        <tr>
                            <th>Affected Systems</th>
                            <td>{{ affected_systems }}</td>
                        </tr>
                        {% endif %}
                    </table>
                    
                    {% if related_alerts %}
                    <div class="related-alerts">
                        <h3>Related Alerts</h3>
                        <ul>
                            {% for alert in related_alerts %}
                            <li>{{ alert.description }}</li>
                            {% endfor %}
                        </ul>
                    </div>
                    {% endif %}
                    
                    <a href="{{ base_url }}/incidents/{{ incident_id }}/" class="btn">View Incident Details</a>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated message from your Log Detection Platform.</p>
                <p>© {% now "Y" %} Log Detection Platform | Please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    '''
    
    @staticmethod
    def send_alert(subject, message, severity, recipients=None, alert_id=None, source_ip=None, affected_system=None, include_html=True):
        """
        Send an email alert about a security event
        
        Args:
            subject: Email subject line
            message: Plain text message
            severity: Alert severity (critical, high, medium, low)
            recipients: List of email recipients (if None, uses default admins)
            alert_id: ID of the related alert object
            source_ip: Source IP of the threat (optional)
            affected_system: Affected system name (optional)
            include_html: Whether to include HTML version of the email
        """
        if recipients is None:
            # Default to system admins if no recipients specified
            recipients = [admin[1] for admin in settings.ADMINS]
            
        if not recipients:
            logger.warning("No recipients specified for email alert")
            return False
            
        config = SMTPConfiguration.get_active_config()
        if not config:
            logger.error("No active SMTP configuration found")
            return False
            
        # Update Django email settings with our configuration
        settings.EMAIL_HOST = config.host
        settings.EMAIL_PORT = config.port
        settings.EMAIL_HOST_USER = config.username
        settings.EMAIL_HOST_PASSWORD = config.password
        settings.EMAIL_USE_TLS = config.use_tls
        settings.EMAIL_USE_SSL = config.use_ssl
        settings.DEFAULT_FROM_EMAIL = config.default_from_email
        
        # Create records for each recipient
        email_records = []
        for recipient in recipients:
            email_alert = EmailAlert(
                subject=subject,
                message=message,
                recipient=recipient,
                severity=severity,
                related_alert_id=alert_id
            )
            email_alert.save()
            email_records.append(email_alert)
            
        try:
            # Prepare HTML version if requested
            html_message = None
            if include_html:
                from django.template import Context, Template
                from django.contrib.sites.models import Site
                
                # Get base URL for links in email
                try:
                    site = Site.objects.get_current()
                    base_url = f"https://{site.domain}"
                except:
                    base_url = settings.BASE_URL if hasattr(settings, 'BASE_URL') else ''
                
                context = {
                    'subject': subject,
                    'message': message,
                    'severity': severity,
                    'alert_id': alert_id,
                    'source_ip': source_ip,
                    'affected_system': affected_system,
                    'timestamp': timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'base_url': base_url,
                    'alert_details': True
                }
                
                # Use the inline template instead of a file
                template = Template(EmailNotifier.ALERT_EMAIL_TEMPLATE)
                html_message = template.render(Context(context))
            
            # Create email message
            email = EmailMultiAlternatives(
                subject=subject,
                body=message,
                from_email=config.default_from_email,
                to=recipients
            )
            
            # Attach HTML version if available
            if html_message:
                email.attach_alternative(html_message, "text/html")
                
            # Send email
            email.send(fail_silently=False)
            
            # Update records
            for record in email_records:
                record.status = 'sent'
                record.sent_at = timezone.now()
                record.save()
                
            logger.info(f"Successfully sent email alert to {len(recipients)} recipients")
            return True
            
        except Exception as e:
            logger.error(f"Error sending email alert: {e}")
            
            # Update records with error
            for record in email_records:
                record.status = 'failed'
                record.error_message = str(e)
                record.save()
                
            return False
    
    @staticmethod
    def send_incident_notification(incident, recipients=None):
        """
        Send an email notification about a security incident
        
        Args:
            incident: The Incident object
            recipients: List of email recipients (if None, uses default admins)
        """
        if recipients is None:
            # Default to system admins if no recipients specified
            recipients = [admin[1] for admin in settings.ADMINS]
            
        if not recipients:
            logger.warning("No recipients specified for incident notification")
            return False
        
        # Format the incident information
        subject = f"[{incident.severity.upper()}] Security Incident: {incident.name}"
        message = f"{incident.description}\n\n"
        message += f"Status: {incident.status}\n"
        message += f"Start Time: {incident.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        if incident.affected_ips:
            message += f"Affected IPs: {incident.affected_ips}\n"
            
        if incident.affected_users:
            message += f"Affected Users: {incident.affected_users}\n"
            
        # Add related threats information
        related_threats_count = incident.threats.count()
        if related_threats_count > 0:
            message += f"\nRelated Threats: {related_threats_count}\n"
            
            # List first 5 threats
            for threat in incident.threats.all()[:5]:
                message += f"- {threat.description[:100]}...\n"
                
            if related_threats_count > 5:
                message += f"... and {related_threats_count - 5} more\n"
                
        # Get HTML content
        try:
            from django.template import Context, Template
            from django.contrib.sites.models import Site
            
            # Get base URL for links in email
            try:
                site = Site.objects.get_current()
                base_url = f"https://{site.domain}"
            except:
                base_url = settings.BASE_URL if hasattr(settings, 'BASE_URL') else ''
            
            context = {
                'subject': subject,
                'message': incident.description,
                'severity': incident.severity,
                'incident_id': incident.id,
                'status': incident.status,
                'start_time': incident.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': incident.end_time.strftime('%Y-%m-%d %H:%M:%S') if incident.end_time else 'Ongoing',
                'affected_systems': incident.affected_ips,
                'related_alerts': incident.threats.all()[:5],
                'base_url': base_url
            }
            
            # Use the inline template instead of a file
            template = Template(EmailNotifier.INCIDENT_EMAIL_TEMPLATE)
            html_message = template.render(Context(context))
            
            # Configure and send email
            config = SMTPConfiguration.get_active_config()
            if not config:
                logger.error("No active SMTP configuration found")
                return False
                
            # Update Django email settings with our configuration
            settings.EMAIL_HOST = config.host
            settings.EMAIL_PORT = config.port
            settings.EMAIL_HOST_USER = config.username
            settings.EMAIL_HOST_PASSWORD = config.password
            settings.EMAIL_USE_TLS = config.use_tls
            settings.EMAIL_USE_SSL = config.use_ssl
            settings.DEFAULT_FROM_EMAIL = config.default_from_email
            
            # Create email message
            email = EmailMultiAlternatives(
                subject=subject,
                body=message,
                from_email=config.default_from_email,
                to=recipients
            )
            
            # Attach HTML version
            email.attach_alternative(html_message, "text/html")
                
            # Send email
            email.send(fail_silently=False)
            
            logger.info(f"Successfully sent incident notification to {len(recipients)} recipients")
            return True
            
        except Exception as e:
            logger.error(f"Error sending incident notification: {e}")
            return False
