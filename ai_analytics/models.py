from django.db import models
from django.utils import timezone
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from datetime import timedelta

class AIReport(models.Model):
    """AI-generated security reports with caching"""
    REPORT_TYPES = [
        ('security_summary', 'Security Summary'),
        ('incident_analysis', 'Incident Analysis'),
        ('root_cause', 'Root Cause Analysis'),
        ('anomaly_detection', 'Anomaly Detection'),
        ('prediction', 'Predictive Analysis'),
        ('user_behavior', 'User Behavior Analysis'),
        ('cross_source', 'Cross-Source Correlation')
    ]
    
    SOURCE_FILTERS = [
        ('all', 'All Sources'),
        ('apache', 'Apache Logs'),
        ('mysql', 'MySQL Logs'),
    ]
    
    SEVERITY_FILTERS = [
        ('all', 'All Severities'),
        ('high', 'High Severity'),
        ('medium', 'Medium Severity'),
        ('low', 'Low Severity'),
    ]
    
    title = models.CharField(max_length=200)
    report_type = models.CharField(max_length=50, choices=REPORT_TYPES)
    content = models.TextField()
    generated_at = models.DateTimeField(default=timezone.now)
    time_period_start = models.DateTimeField()
    time_period_end = models.DateTimeField()
    source_filter = models.CharField(
        max_length=20, 
        choices=SOURCE_FILTERS, 
        default='all'
    )
    severity_filter = models.CharField(
        max_length=20, 
        choices=SEVERITY_FILTERS, 
        default='all'
    )
    
    # Cache management
    is_cached = models.BooleanField(default=True)
    cache_valid_until = models.DateTimeField(
        default=lambda: timezone.now() + timedelta(hours=getattr(settings, 'AI_REPORT_CACHE_HOURS', 24))
    )
    tokens_used = models.IntegerField(default=0)
    
    # User who requested the report
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='ai_reports'
    )
    
    # Related entities
    related_threats = models.ManyToManyField(
        'threat_detection.Threat',
        blank=True,
        related_name='ai_reports'
    )
    related_incidents = models.ManyToManyField(
        'threat_detection.Incident',
        blank=True,
        related_name='ai_reports'
    )
    
    def __str__(self):
        return f"{self.get_report_type_display()} - {self.generated_at.strftime('%Y-%m-%d %H:%M')}"
    
    def save(self, *args, **kwargs):
        # Ensure time periods are valid
        if self.time_period_start > self.time_period_end:
            self.time_period_start, self.time_period_end = self.time_period_end, self.time_period_start
            
        # Ensure timezone-aware dates
        if timezone.is_naive(self.time_period_start):
            self.time_period_start = timezone.make_aware(self.time_period_start)
        if timezone.is_naive(self.time_period_end):
            self.time_period_end = timezone.make_aware(self.time_period_end)
            
        # Ensure cache validity is set
        if not self.cache_valid_until:
            hours = getattr(settings, 'AI_REPORT_CACHE_HOURS', 24)
            self.cache_valid_until = timezone.now() + timedelta(hours=hours)
            
        super().save(*args, **kwargs)
    
    @property
    def is_cache_valid(self):
        return timezone.now() < self.cache_valid_until
        
    @property
    def time_period_duration(self):
        """Return duration of analysis period in hours"""
        delta = self.time_period_end - self.time_period_start
        return round(delta.total_seconds() / 3600, 1)  # Convert to hours
    
    class Meta:
        verbose_name = 'AI Report'
        verbose_name_plural = 'AI Reports'
        ordering = ['-generated_at']
        indexes = [
            models.Index(fields=['report_type']),
            models.Index(fields=['generated_at']),
            models.Index(fields=['time_period_start', 'time_period_end']),
            models.Index(fields=['source_filter']),
            models.Index(fields=['created_by']),
        ]


class AIReportFeedback(models.Model):
    """User feedback on AI reports for model improvement"""
    RATING_CHOICES = [
        (1, 'Poor'),
        (2, 'Fair'),
        (3, 'Good'),
        (4, 'Very Good'),
        (5, 'Excellent')
    ]
    
    report = models.ForeignKey(AIReport, on_delete=models.CASCADE, related_name='feedback')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    rating = models.IntegerField(
        choices=RATING_CHOICES,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    comments = models.TextField(blank=True, null=True)
    submitted_at = models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return f"Feedback on {self.report} by {self.user.username}: {self.get_rating_display()}"
    
    class Meta:
        verbose_name = 'Report Feedback'
        verbose_name_plural = 'Report Feedback'
        unique_together = ['report', 'user']
        ordering = ['-submitted_at']
        indexes = [
            models.Index(fields=['report']),
            models.Index(fields=['user']),
            models.Index(fields=['rating']),
        ]