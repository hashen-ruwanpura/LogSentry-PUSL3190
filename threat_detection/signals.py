from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
import json
import logging

from log_ingestion.models import ParsedLog
from .models import Threat, Incident
from threat_detection.rules import RuleEngine
from notifications.notifiers import EmailNotifier, SMSNotifier, SlackNotifier

logger = logging.getLogger(__name__)

@receiver(post_save, sender=ParsedLog)
def analyze_log_for_threats(sender, instance, created, **kwargs):
    """
    Signal handler that analyzes each newly saved ParsedLog for threats.
    This enables real-time threat detection as logs are parsed.
    """
    if created:  # Only process newly created logs
        try:
            # Initialize the rule engine for real-time threat detection
            rule_engine = RuleEngine()
            
            # Analyze the log for threats
            threats = rule_engine.analyze_log(instance)
            
            # If threats are detected, trigger notifications
            if threats:
                logger.warning(f"Threats detected: {threats}")
                
                # Get all available notifiers
                notifiers = [
                    EmailNotifier(),
                    SMSNotifier(),
                    SlackNotifier()
                ]
                
                # Send notifications through all available channels
                for notifier in notifiers:
                    try:
                        notifier.send_notification(
                            subject=f"Security threat detected from {instance.source_ip}",
                            message=f"""
                            Threat details:
                            - IP Address: {instance.source_ip}
                            - Timestamp: {instance.timestamp}
                            - Path: {instance.path}
                            - Method: {instance.http_method}
                            - Status: {instance.status_code}
                            - User Agent: {instance.user_agent}
                            - Threat type: {', '.join(threat.rule_name for threat in threats)}
                            """
                        )
                    except Exception as e:
                        logger.error(f"Failed to send notification via {notifier.__class__.__name__}: {e}")
                        
        except Exception as e:
            logger.error(f"Error in threat analysis: {e}")

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