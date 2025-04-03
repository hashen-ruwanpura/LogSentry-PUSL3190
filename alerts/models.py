from django.db import models
from django.contrib.auth.models import User

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
    
    timestamp = models.DateTimeField(auto_now_add=True)
    type = models.CharField(max_length=50, choices=TYPE_CHOICES)
    source = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    description = models.TextField()
    ip_address = models.CharField(max_length=50, blank=True, null=True)
    user = models.CharField(max_length=100, blank=True, null=True)
    affected_systems = models.TextField(blank=True, null=True)
    mitre_tactics = models.TextField(blank=True, null=True)
    recommendation = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return f"Alert {self.id}: {self.type} ({self.severity})"

class AlertNote(models.Model):
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='notes')
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    def __str__(self):
        return f"Note on Alert {self.alert.id} by {self.created_by}"
