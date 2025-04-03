from django.db import models
from django.utils import timezone
from log_ingestion.models import ParsedLog

class DetectionRule(models.Model):
    """Rule for detecting threats in logs"""
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    name = models.CharField(max_length=100)
    description = models.TextField()
    rule_type = models.CharField(max_length=50)  # sql_injection, brute_force, etc.
    pattern = models.TextField(blank=True, null=True)  # Regex pattern or other criteria
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    mitre_technique = models.CharField(max_length=20, blank=True, null=True)  # MITRE ATT&CK technique ID
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} ({self.severity})"

class Threat(models.Model):
    """Detected threat based on a rule"""
    STATUS_CHOICES = [
        ('new', 'New'),
        ('investigating', 'Investigating'),
        ('confirmed', 'Confirmed'),
        ('false_positive', 'False Positive'),
        ('resolved', 'Resolved'),
    ]
    
    rule = models.ForeignKey(DetectionRule, on_delete=models.CASCADE)
    parsed_log = models.ForeignKey(ParsedLog, on_delete=models.CASCADE)
    severity = models.CharField(max_length=10, choices=DetectionRule.SEVERITY_CHOICES)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='new')
    description = models.TextField()
    source_ip = models.GenericIPAddressField(blank=True, null=True)
    user_id = models.CharField(max_length=255, blank=True, null=True)
    mitre_technique = models.CharField(max_length=20, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.rule.name} - {self.created_at}"

class Incident(models.Model):
    """Security incident composed of multiple related threats"""
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('investigating', 'Investigating'),
        ('contained', 'Contained'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]
    
    SEVERITY_CHOICES = DetectionRule.SEVERITY_CHOICES
    
    name = models.CharField(max_length=100)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='open')
    start_time = models.DateTimeField()
    end_time = models.DateTimeField(blank=True, null=True)
    threats = models.ManyToManyField(Threat, related_name='incidents')
    affected_ips = models.TextField(blank=True, null=True)  # Stored as JSON array
    affected_users = models.TextField(blank=True, null=True)  # Stored as JSON array
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} ({self.status})"

class BlacklistedIP(models.Model):
    """IPs blacklisted due to malicious activity"""
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField()
    threat = models.ForeignKey(Threat, on_delete=models.SET_NULL, null=True, blank=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.ip_address} ({self.reason})"
    
    @property
    def is_expired(self):
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at
