from django.db import models
from django.utils import timezone
import json

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
    timestamp = models.DateTimeField(default=timezone.now)
    is_parsed = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.source.source_type} log: {self.timestamp}"

class ParsedLog(models.Model):
    """Parsed and normalized log data"""
    STATUS_CHOICES = [
        ('normal', 'Normal'),
        ('warning', 'Warning'),
        ('suspicious', 'Suspicious'),
        ('attack', 'Attack'),
    ]
    
    raw_log = models.OneToOneField(RawLog, on_delete=models.CASCADE, related_name='parsed')
    timestamp = models.DateTimeField()
    log_level = models.CharField(max_length=20, blank=True, null=True)
    source_ip = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    request_method = models.CharField(max_length=10, blank=True, null=True)
    request_path = models.TextField(blank=True, null=True)
    status_code = models.IntegerField(blank=True, null=True)
    response_size = models.IntegerField(blank=True, null=True)
    user_id = models.CharField(max_length=255, blank=True, null=True)
    query = models.TextField(blank=True, null=True)
    execution_time = models.FloatField(blank=True, null=True)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='normal')
    normalized_data = models.JSONField()
    
    def __str__(self):
        return f"Parsed log: {self.timestamp}"
