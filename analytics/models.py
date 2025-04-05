from django.db import models
from django.conf import settings

class LogReport(models.Model):
    """Model to store parsed and analyzed logs for reporting"""
    LOG_TYPE_CHOICES = [
        ('apache', 'Apache'),
        ('mysql', 'MySQL'),
    ]
    
    SEVERITY_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
    ]
    
    timestamp = models.DateTimeField()
    log_type = models.CharField(max_length=20, choices=LOG_TYPE_CHOICES)
    source_ip = models.GenericIPAddressField()
    country_code = models.CharField(max_length=2, null=True, blank=True)
    country_name = models.CharField(max_length=100, null=True, blank=True)
    threat_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    raw_log = models.TextField()
    
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
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['log_type']),
            models.Index(fields=['severity']),
            models.Index(fields=['status']),
            models.Index(fields=['source_ip']),
        ]
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.log_type} - {self.threat_type} - {self.timestamp}"
