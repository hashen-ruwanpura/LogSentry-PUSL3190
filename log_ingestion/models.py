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

class LogAgent(models.Model):
    """Model for log collection agents installed on remote servers"""
    AGENT_TYPE_CHOICES = [
        ('system', 'System Agent'),
        ('apache', 'Apache Agent'),
        ('mysql', 'MySQL Agent'),
        ('application', 'Application Agent'),
        ('security', 'Security Agent'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('error', 'Error'),
        ('pending', 'Pending'),
    ]
    
    name = models.CharField(max_length=100)
    agent_type = models.CharField(max_length=20, choices=AGENT_TYPE_CHOICES)
    hostname = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    version = models.CharField(max_length=20, null=True, blank=True)
    os_info = models.CharField(max_length=255, null=True, blank=True)
    last_check_in = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Configuration
    collection_interval = models.IntegerField(default=30, help_text="Log collection interval in seconds")
    heartbeat_interval = models.IntegerField(default=60, help_text="Heartbeat interval in seconds")
    log_paths = models.TextField(null=True, blank=True, help_text="Paths to monitor for logs")
    monitored_services = models.CharField(max_length=255, null=True, blank=True)
    encryption_enabled = models.BooleanField(default=True)
    compression_enabled = models.BooleanField(default=True)
    
    # Stats fields
    logs_collected = models.IntegerField(default=0)
    error_count = models.IntegerField(default=0)
    cpu_usage = models.FloatField(null=True, blank=True)
    memory_usage = models.FloatField(null=True, blank=True)
    
    class Meta:
        ordering = ['-last_check_in']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['agent_type']),
            models.Index(fields=['last_check_in']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.agent_type})"

class AgentResourceMetric(models.Model):
    """Resource utilization metrics collected from agents"""
    agent = models.ForeignKey(LogAgent, on_delete=models.CASCADE, related_name='resource_metrics')
    timestamp = models.DateTimeField(default=timezone.now)
    cpu_usage = models.FloatField(help_text="CPU usage percentage (0-100)")
    memory_usage = models.FloatField(help_text="Memory usage percentage (0-100)")
    disk_usage = models.FloatField(help_text="Disk usage percentage (0-100)")
    log_volume = models.FloatField(help_text="Log volume (percentage of allocated space)")
    iops = models.FloatField(null=True, blank=True, help_text="IO operations per second")
    network_in = models.FloatField(null=True, blank=True, help_text="Network inbound KB/s")
    network_out = models.FloatField(null=True, blank=True, help_text="Network outbound KB/s")
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['agent', 'timestamp']),
            models.Index(fields=['timestamp']),
        ]
    
    def __str__(self):
        return f"{self.agent.name} - {self.timestamp.strftime('%Y-%m-%d %H:%M')}"
