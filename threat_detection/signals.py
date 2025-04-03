from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
import json

from log_ingestion.models import ParsedLog
from .models import Threat, Incident
from .rules import RuleEngine

# Create rule engine instance
rule_engine = RuleEngine()

@receiver(post_save, sender=ParsedLog)
def analyze_parsed_log(sender, instance, created, **kwargs):
    """When a log is parsed, analyze it for threats"""
    if created:
        # Apply rules to the newly created parsed log
        threats, _ = rule_engine.analyze_log(instance)
        
        # If threats were detected, check if they should be part of an incident
        for threat in threats:
            check_for_incident(threat)

def check_for_incident(threat):
    """Check if this threat is part of a larger incident"""
    # Skip if no source IP (can't correlate)
    if not threat.source_ip:
        return
        
    # Look for recent threats from the same IP
    recent_timeframe = timezone.now() - timezone.timedelta(hours=1)
    recent_threats = Threat.objects.filter(
        source_ip=threat.source_ip,
        created_at__gte=recent_timeframe
    ).exclude(id=threat.id)
    
    # If we have multiple threats, consider it an incident
    if recent_threats.count() >= 2:
        # Check if already part of an open incident
        existing_incidents = Incident.objects.filter(
            threats__in=[threat.id],
            status__in=['open', 'investigating']
        )
        
        if existing_incidents.exists():
            # Already part of an incident
            incident = existing_incidents.first()
            
            # Add recent threats that aren't already included
            for recent_threat in recent_threats:
                if recent_threat not in incident.threats.all():
                    incident.threats.add(recent_threat)
            
            # Update severity if needed
            if threat.severity == 'critical' and incident.severity != 'critical':
                incident.severity = 'critical'
                incident.save(update_fields=['severity', 'updated_at'])
                
        else:
            # Create new incident
            affected_ips = set([threat.source_ip])
            affected_users = set()
            
            if threat.user_id:
                affected_users.add(threat.user_id)
                
            for recent_threat in recent_threats:
                if recent_threat.source_ip:
                    affected_ips.add(recent_threat.source_ip)
                if recent_threat.user_id:
                    affected_users.add(recent_threat.user_id)
            
            # Determine highest severity
            severities = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
            highest_severity = 'low'
            
            for t in [threat] + list(recent_threats):
                if severities.get(t.severity, 0) > severities.get(highest_severity, 0):
                    highest_severity = t.severity
            
            # Create the incident
            incident = Incident.objects.create(
                name=f"Multiple threats from {threat.source_ip}",
                description=f"Multiple security threats detected from IP {threat.source_ip}",
                severity=highest_severity,
                start_time=recent_threats.order_by('created_at').first().created_at,
                affected_ips=json.dumps(list(affected_ips)),
                affected_users=json.dumps(list(affected_users)) if affected_users else None
            )
            
            # Add all related threats
            incident.threats.add(threat, *recent_threats)