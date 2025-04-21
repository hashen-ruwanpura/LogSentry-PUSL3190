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
    """Parsed and normalized log data"""
    STATUS_CHOICES = [
        ('normal', 'Normal'),
        ('warning', 'Warning'),
        ('suspicious', 'Suspicious'),
        ('attack', 'Attack'),
    ]
    
    # Make raw_log field optional to support streaming logs that don't have RawLog entries
    raw_log = models.OneToOneField(RawLog, on_delete=models.CASCADE, related_name='parsed',
                                   null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)  # Add default
    log_level = models.CharField(max_length=20, blank=True, null=True)
    source_ip = models.GenericIPAddressField(blank=True, null=True, db_index=True)  # Add index for IP lookups
    user_agent = models.TextField(blank=True, null=True)
    request_method = models.CharField(max_length=10, blank=True, null=True)
    request_path = models.TextField(blank=True, null=True)
    status_code = models.IntegerField(blank=True, null=True)
    response_size = models.IntegerField(blank=True, null=True)
    user_id = models.CharField(max_length=255, blank=True, null=True)
    query = models.TextField(blank=True, null=True)
    execution_time = models.FloatField(blank=True, null=True)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='normal', db_index=True)  # Add index
    normalized_data = models.JSONField()
    
    # New fields for real-time analysis
    analyzed = models.BooleanField(default=False, help_text="Whether this log has been analyzed for threats")
    analysis_time = models.DateTimeField(null=True, blank=True, help_text="When the log was analyzed")
    source_type = models.CharField(max_length=20, blank=True, null=True, 
                                  help_text="Type of log (apache, mysql, etc)")
    
    def __str__(self):
        return f"Parsed log: {self.timestamp}"
    
    class Meta:
        # Add indexes for better performance in real-time queries
        indexes = [
            models.Index(fields=['analyzed', 'timestamp']),
            models.Index(fields=['status', 'source_ip']),
        ]
        
    def mark_analyzed(self):
        """Mark this log as analyzed for threats"""
        self.analyzed = True
        self.analysis_time = timezone.now()
        self.save(update_fields=['analyzed', 'analysis_time'])
