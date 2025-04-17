from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models import Count, Q

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
