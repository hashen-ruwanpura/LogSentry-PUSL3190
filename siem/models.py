import logging
from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

# Configure logger
logger = logging.getLogger(__name__)

def validate_modifier_range(value):
    if not 0 < value <= 10:
        raise ValidationError('%s not in 0.1-10 range' % value)

class ApacheLogEntry(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    client_ip = models.GenericIPAddressField()
    request_method = models.CharField(max_length=10)  # GET, POST, etc.
    request_url = models.CharField(max_length=2048)
    status_code = models.IntegerField()
    bytes_sent = models.IntegerField()
    referrer = models.URLField(max_length=2048, null=True, blank=True)
    user_agent = models.CharField(max_length=256)
    server_name = models.CharField(max_length=100)
    request_time = models.FloatField(help_text="Request processing time in seconds")
    is_error = models.BooleanField(default=False)
    error_message = models.TextField(null=True, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['status_code']),
            models.Index(fields=['client_ip']),
        ]

class MySQLLogEntry(models.Model):
    SEVERITY_CHOICES = [
        ('ERROR', 'Error'),
        ('WARNING', 'Warning'),
        ('INFO', 'Information'),
        ('NOTE', 'Note'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    thread_id = models.IntegerField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    subsystem = models.CharField(max_length=50)
    error_code = models.CharField(max_length=10, null=True, blank=True)
    message = models.TextField()
    user = models.CharField(max_length=32, null=True, blank=True)
    host = models.CharField(max_length=255)
    query = models.TextField(null=True, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['severity']),
            models.Index(fields=['error_code']),
        ]

class SecurityAlert(models.Model):
    ALERT_TYPES = [
        ('APACHE', 'Apache Alert'),
        ('MYSQL', 'MySQL Alert'),
    ]
    
    created_at = models.DateTimeField(auto_now_add=True)
    alert_type = models.CharField(max_length=10, choices=ALERT_TYPES)
    severity = models.IntegerField(choices=[
        (1, 'Low'),
        (2, 'Medium'),
        (3, 'High'),
        (4, 'Critical'),
    ])
    title = models.CharField(max_length=200)
    description = models.TextField()
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    is_resolved = models.BooleanField(default=False)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    apache_log = models.ForeignKey(ApacheLogEntry, on_delete=models.CASCADE, null=True, blank=True)
    mysql_log = models.ForeignKey(MySQLLogEntry, on_delete=models.CASCADE, null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['created_at']),
            models.Index(fields=['alert_type']),
            models.Index(fields=['severity']),
        ]
