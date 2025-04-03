from django.db import models
from django.contrib.auth.models import User


class Threat(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    detected_at = models.DateTimeField(auto_now_add=True)

class Incident(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    detected_at = models.DateTimeField(auto_now_add=True)

class Log(models.Model):
    source = models.CharField(max_length=100)
    message = models.TextField()
    logged_at = models.DateTimeField(auto_now_add=True)

class DashboardWidget(models.Model):
    """Widget configuration for user dashboards"""
    
    WIDGET_TYPES = [
        ('threat_summary', 'Threat Summary'),
        ('recent_incidents', 'Recent Incidents'),
        ('top_attackers', 'Top Attackers'),
        ('error_rate', 'Error Rate Chart'),
        ('traffic_volume', 'Traffic Volume'),
        ('status_codes', 'HTTP Status Codes'),
        ('query_performance', 'SQL Query Performance'),
        ('failed_logins', 'Failed Logins'),
        ('geographic_map', 'Geographic Map'),
        ('mitre_techniques', 'MITRE Techniques'),
    ]
    
    REFRESH_RATES = [
        (0, 'No automatic refresh'),
        (30, 'Every 30 seconds'),
        (60, 'Every minute'),
        (300, 'Every 5 minutes'),
        (600, 'Every 10 minutes'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='dashboard_widgets')
    widget_type = models.CharField(max_length=50, choices=WIDGET_TYPES)
    title = models.CharField(max_length=100)
    position = models.IntegerField(default=0)
    size = models.CharField(max_length=20, default='medium')  # small, medium, large
    refresh_rate = models.IntegerField(choices=REFRESH_RATES, default=60)
    configuration = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['position']
    
    def __str__(self):
        return f"{self.title} ({self.widget_type})"

class SavedSearch(models.Model):
    """User-saved search queries"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='saved_searches')
    name = models.CharField(max_length=100)
    query = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name

class UserDashboard(models.Model):
    """Custom dashboard configuration for users"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='dashboards')
    name = models.CharField(max_length=100)
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = [['user', 'is_default']]
    
    def __str__(self):
        return f"{self.name} ({'Default' if self.is_default else 'Custom'})"
    
    def save(self, *args, **kwargs):
        # Ensure only one default dashboard per user
        if self.is_default:
            UserDashboard.objects.filter(user=self.user, is_default=True).update(is_default=False)
        super().save(*args, **kwargs)
