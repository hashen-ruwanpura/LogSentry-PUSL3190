from django.db import models
from django.utils import timezone
import json
from django.db.models import Index

class LogSource(models.Model):
    """Configuration for a log source"""
    TYPE_CHOICES = [
        ('apache_access', 'Apache Access Log'),
        ('apache_error', 'Apache Error Log'),
        ('mysql_general', 'MySQL General Log'),
        ('mysql_slow', 'MySQL Slow Query Log'),
        ('mysql_error', 'MySQL Error Log'),
    ]
    
    name = models.CharField(max_length=100)
    source_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    file_path = models.CharField(max_length=255)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # New fields for real-time collection
    use_filebeat = models.BooleanField(default=False, help_text="Use Filebeat for real-time collection")
    kafka_topic = models.CharField(max_length=100, default='raw_logs', help_text="Kafka topic for log messages")
    
    def __str__(self):
        return f"{self.name} ({self.source_type})"

class LogFilePosition(models.Model):
    """Track file positions for incremental log processing"""
    source = models.ForeignKey(LogSource, on_delete=models.CASCADE)
    file_path = models.CharField(max_length=255)
    position = models.BigIntegerField(default=0)
    last_updated = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('source', 'file_path')
    
    def __str__(self):
        return f"Position for {self.file_path}: {self.position}"

class RawLog(models.Model):
    """Raw log entries before parsing"""
    source = models.ForeignKey(LogSource, on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)  # Add default
    is_parsed = models.BooleanField(default=False)
    # New field for real-time processing
    processing_status = models.CharField(max_length=20, 
                                        default='new',
                                        choices=[('new', 'New'), 
                                                ('processing', 'Processing'),
                                                ('parsed', 'Parsed'),
                                                ('error', 'Error')])
    
    def __str__(self):
        return f"{self.source.source_type} log: {self.timestamp}"
    
    class Meta:
        # Add indexes for better performance in real-time queries
        indexes = [
            models.Index(fields=['is_parsed', 'timestamp']),
            models.Index(fields=['processing_status']),
        ]

class ParsedLog(models.Model):
    """Parsed and normalized log entries"""
    raw_log = models.ForeignKey('RawLog', on_delete=models.CASCADE, null=True, blank=True)
    timestamp = models.DateTimeField()
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    source_type = models.CharField(max_length=50, blank=True)
    log_level = models.CharField(max_length=20, null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    request_method = models.CharField(max_length=20, null=True, blank=True)
    request_path = models.TextField(null=True, blank=True)  # This will store the path
    status_code = models.IntegerField(null=True, blank=True)
    response_size = models.IntegerField(null=True, blank=True)
    user_id = models.CharField(max_length=100, null=True, blank=True)
    query = models.TextField(null=True, blank=True)
    execution_time = models.FloatField(null=True, blank=True)
    status = models.CharField(max_length=20, default='normal')
    normalized_data = models.JSONField(default=dict)
    analyzed = models.BooleanField(default=False)
    analysis_time = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.source_type} log ({self.status}): {self.timestamp}"
    
    @property
    def path(self):
        """Dynamic property to access the request path"""
        # First check if it's directly in our fields
        if hasattr(self, 'request_path') and self.request_path:
            return self.request_path
            
        # Then check in normalized_data
        if self.normalized_data and 'request_path' in self.normalized_data:
            return self.normalized_data['request_path']
        
        # Try other possible keys
        for key in ['path', 'url', 'uri']:
            if self.normalized_data and key in self.normalized_data:
                return self.normalized_data[key]
        
        # Default to empty string if not found
        return ''
