from django.db import models
from django.conf import settings
from django.utils import timezone

class LogReport(models.Model):
    """Model to store processed log reports/threats for the reporting system"""
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]
    
    STATUS_CHOICES = [
        ('Open', 'Open'),
        ('In Progress', 'In Progress'),
        ('Resolved', 'Resolved'),
    ]
    
    timestamp = models.DateTimeField(default=timezone.now)
    log_type = models.CharField(max_length=50, blank=True, null=True)  # 'apache', 'mysql', etc.
    source_ip = models.CharField(max_length=50, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    threat_type = models.CharField(max_length=100, blank=True, null=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='low')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Open')
    raw_log_id = models.IntegerField(blank=True, null=True)  # Reference to original raw log if available
    description = models.TextField(blank=True, null=True)
    
    # Apache specific fields
    request_method = models.CharField(max_length=10, null=True, blank=True)
    request_path = models.TextField(null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    response_size = models.IntegerField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    
    # MySQL specific fields
    database = models.CharField(max_length=100, null=True, blank=True)
    query_type = models.CharField(max_length=50, null=True, blank=True)
    
    # Additional fields
    notes = models.TextField(null=True, blank=True)
    resolved_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name='resolved_reports')
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['severity']),
            models.Index(fields=['source_ip']),
            models.Index(fields=['log_type']),
        ]
    
    def __str__(self):
        return f"{self.timestamp} - {self.threat_type} ({self.severity})"
