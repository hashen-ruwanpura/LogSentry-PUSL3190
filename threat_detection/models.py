from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
import logging

# Configure logger
logger = logging.getLogger(__name__)

class DetectionRule(models.Model):
    """Model for detection rules"""
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    name = models.CharField(max_length=100)
    description = models.TextField()
    rule_type = models.CharField(max_length=50, db_index=True)
    pattern = models.TextField(blank=True, null=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    enabled = models.BooleanField(default=True)
    
    # Added fields for MITRE ATT&CK integration
    mitre_technique_id = models.CharField(max_length=20, blank=True, null=True)
    mitre_tactic = models.CharField(max_length=50, blank=True, null=True)
    
    # Recommendation field - consolidate instead of creating a separate table
    recommendation_template = models.TextField(blank=True, null=True, 
                                              help_text="Template with {placeholders} for dynamic recommendations")
    
    class Meta:
        indexes = [
            models.Index(fields=['rule_type']),
            models.Index(fields=['severity']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.rule_type})"
    
    def save(self, *args, **kwargs):
        """Override save to add MITRE information if missing"""
        if not self.mitre_technique_id and not self.mitre_tactic:
            from .mitre_mapping import mitre_mapper
            tactic, technique_id, _ = mitre_mapper.map_threat(self.rule_type or self.name, {'description': self.description})
            self.mitre_tactic = tactic
            self.mitre_technique_id = technique_id
            
        super().save(*args, **kwargs)


class Threat(models.Model):
    """Model for detected threats"""
    STATUS_CHOICES = [
        ('new', 'New'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
        ('ignored', 'Ignored'),
    ]
    
    rule = models.ForeignKey(DetectionRule, on_delete=models.SET_NULL, null=True, related_name='threats')
    parsed_log = models.ForeignKey('log_ingestion.ParsedLog', on_delete=models.SET_NULL, null=True)
    
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    severity = models.CharField(max_length=10, choices=DetectionRule.SEVERITY_CHOICES, db_index=True)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='new', db_index=True)
    
    description = models.TextField()
    source_ip = models.GenericIPAddressField(blank=True, null=True, db_index=True)
    user_id = models.CharField(max_length=100, blank=True, null=True)
    affected_system = models.CharField(max_length=100, blank=True, null=True)
    
    # Fields for MITRE ATT&CK
    mitre_technique = models.CharField(max_length=20, blank=True, null=True)
    mitre_tactic = models.CharField(max_length=50, blank=True, null=True)
    
    # Analysis and intelligence data
    analysis_data = models.JSONField(blank=True, null=True)
    
    # For efficiency, include the recommendation directly
    recommendation = models.TextField(blank=True, null=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['created_at']),
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['source_ip']),
        ]
        
    def __str__(self):
        return f"Threat {self.id}: {self.description[:50]}"
    
    def get_recommendation(self):
        """Get or generate recommendation"""
        if self.recommendation:
            return self.recommendation
            
        if self.rule and self.rule.recommendation_template:
            # Replace placeholders with context
            recommendation = self.rule.recommendation_template
            context = {
                'ip': self.source_ip or 'unknown',
                'user': self.user_id or 'unknown',
                'path': self.parsed_log.request_path if self.parsed_log else 'unknown',
                'pattern': self.rule.pattern or 'unknown',
                'timestamp': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            }
            
            for key, value in context.items():
                recommendation = recommendation.replace(f"{{{key}}}", str(value))
            
            return recommendation
        
        return "No specific recommendation available."


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


# Add this model to store AI analyses for threats
class ThreatAnalysis(models.Model):
    """Stores AI-generated analyses for security threats/alerts"""
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE, related_name='ai_analyses')
    analysis_type = models.CharField(max_length=20, 
                                    choices=[
                                        ('analyze', 'General Analysis'),
                                        ('explain', 'Explanation'),
                                        ('suggest', 'Suggested Solutions'),
                                        ('risk', 'Risk Assessment'),
                                        ('related', 'Related Threats'),
                                    ], default='analyze')
    content = models.TextField()
    generated_at = models.DateTimeField(auto_now_add=True)
    tokens_used = models.IntegerField(default=0)
    
    class Meta:
        indexes = [
            models.Index(fields=['threat', 'analysis_type']),
            models.Index(fields=['generated_at']),
        ]
        unique_together = ['threat', 'analysis_type']  # One analysis per type per threat
        
    def __str__(self):
        return f"{self.analysis_type.title()} for Threat #{self.threat.id}"
