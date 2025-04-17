from django.db import models
from django.utils import timezone
import logging
from .models import Threat

# Configure logger
logger = logging.getLogger(__name__)

class HistoricalAnalyzer:
    """Analyzes historical attack patterns"""
    
    @staticmethod
    def find_similar_attacks(threat, days=30, limit=5):
        """Find similar historical attacks"""
        # Define similarity criteria
        if not threat.source_ip:
            return []
            
        # Look for similar threats
        start_date = timezone.now() - timezone.timedelta(days=days)
        similar_threats = Threat.objects.filter(
            models.Q(source_ip=threat.source_ip) | 
            models.Q(rule_id=threat.rule_id),
            created_at__gte=start_date,
            id__lt=threat.id  # Only older threats
        ).order_by('-created_at')[:limit]
        
        return list(similar_threats)
    
    @staticmethod
    def get_attack_progression(source_ip, days=7):
        """Get progression of attacks from a specific source"""
        if not source_ip:
            return []
            
        start_date = timezone.now() - timezone.timedelta(days=days)
        threats = Threat.objects.filter(
            source_ip=source_ip,
            created_at__gte=start_date
        ).order_by('created_at')
        
        # Group by day
        progression = []
        current_date = None
        current_group = None
        
        for threat in threats:
            threat_date = threat.created_at.date()
            if threat_date != current_date:
                if current_group:
                    progression.append(current_group)
                current_date = threat_date
                current_group = {
                    'date': current_date,
                    'threats': [],
                    'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                }
            
            current_group['threats'].append(threat)
            current_group['severity_counts'][threat.severity] += 1
        
        if current_group:
            progression.append(current_group)
            
        return progression

    @staticmethod
    def get_effectiveness_metrics(days=30):
        """Get metrics on effectiveness of security measures"""
        start_date = timezone.now() - timezone.timedelta(days=days)
        
        # Total threats
        total_threats = Threat.objects.filter(created_at__gte=start_date).count()
        
        # Resolved threats
        resolved = Threat.objects.filter(
            created_at__gte=start_date,
            status__in=['resolved', 'false_positive']
        ).count()
        
        # Average time to resolution
        resolved_threats = Threat.objects.filter(
            created_at__gte=start_date,
            status='resolved'
        )
        
        total_resolution_time = timezone.timedelta(0)
        count = 0
        
        for threat in resolved_threats:
            # Use the updated_at as proxy for resolution time
            resolution_time = threat.updated_at - threat.created_at
            total_resolution_time += resolution_time
            count += 1
            
        avg_resolution_time = total_resolution_time / count if count > 0 else None
        
        # Calculate metrics
        return {
            'total_threats': total_threats,
            'resolved_threats': resolved,
            'resolution_rate': (resolved / total_threats) if total_threats > 0 else 0,
            'avg_resolution_time': avg_resolution_time,
        }