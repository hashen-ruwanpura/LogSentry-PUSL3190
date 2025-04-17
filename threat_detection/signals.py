from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
import json
import logging

from log_ingestion.models import ParsedLog
from .models import Threat, Incident
from threat_detection.rules import RuleEngine
from .integrations import ThreatIntelligence

# Configure logger
logger = logging.getLogger(__name__)

# Import notification system if it exists, otherwise provide a mock
try:
    from notifications import notifiers
    has_notifiers = True
except ImportError:
    has_notifiers = False
    logger.warning("Notifications module not found, using mock notifier")
    
    class MockNotifier:
        @staticmethod
        def send_alert(title, message, severity, recipients=None):
            logger.info(f"MOCK NOTIFICATION - {severity}: {title} - {message}")
    
    class notifiers:
        email = MockNotifier()
        slack = MockNotifier()

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
                notifiers_list = [
                    notifiers.email,
                    notifiers.slack
                ]
                
                # Send notifications through all available channels
                for notifier in notifiers_list:
                    try:
                        notifier.send_alert(
                            title=f"Security threat detected from {instance.source_ip}",
                            message=f"""
                            Threat details:
                            - IP Address: {instance.source_ip}
                            - Timestamp: {instance.timestamp}
                            - Path: {instance.path}
                            - Method: {instance.http_method}
                            - Status: {instance.status_code}
                            - User Agent: {instance.user_agent}
                            - Threat type: {', '.join(threat.rule_name for threat in threats)}
                            """,
                            severity='high'
                        )
                    except Exception as e:
                        logger.error(f"Failed to send notification via {notifier.__class__.__name__}: {e}")
                        
        except Exception as e:
            logger.error(f"Error in threat analysis: {e}")

@receiver(post_save, sender=Threat)
def enrich_threat_with_intelligence(sender, instance, created, **kwargs):
    """Enrich threat data with threat intelligence"""
    if created and instance.source_ip:
        try:
            # Get threat intelligence data
            ti_data = ThreatIntelligence.check_ip_reputation(instance.source_ip)
            
            # Update threat with intelligence data
            if ti_data:
                # Store in JSON field
                if not instance.analysis_data:
                    instance.analysis_data = {}
                instance.analysis_data['threat_intelligence'] = ti_data
                
                # Increase severity if highly malicious
                ti_score = ti_data.get('abuseipdb', {}).get('score', 0)
                ti_score = ti_score or ti_data.get('mock', {}).get('score', 0)
                
                if ti_score > 80 and instance.severity != 'critical':
                    instance.severity = 'high'  # Upgrade severity
                
                instance.save(update_fields=['analysis_data', 'severity'])
                logger.info(f"Enriched threat {instance.id} with threat intelligence")
        except Exception as e:
            logger.error(f"Error enriching threat with intelligence: {e}")

@receiver(post_save, sender=Threat)
def notify_about_threat(sender, instance, created, **kwargs):
    """Send notification about newly detected threats"""
    if created or (kwargs.get('update_fields') and 'severity' in kwargs.get('update_fields')):
        try:
            # Only notify about high and critical threats
            if instance.severity in ['high', 'critical']:
                title = f"{instance.severity.upper()} Security Threat Detected"
                message = f"Description: {instance.description}\n"
                message += f"Source IP: {instance.source_ip or 'unknown'}\n"
                message += f"User: {instance.user_id or 'unknown'}\n"
                
                if instance.analysis_data and 'threat_intelligence' in instance.analysis_data:
                    ti = instance.analysis_data['threat_intelligence']
                    if 'abuseipdb' in ti:
                        message += f"Reputation Score: {ti['abuseipdb']['score']}/100\n"
                    elif 'mock' in ti:
                        message += f"Reputation Score: {ti['mock']['score']}/100\n"
                
                # Send email notification
                if has_notifiers:
                    notifiers.email.send_alert(title, message, instance.severity)
                    notifiers.slack.send_alert(title, message, instance.severity)
                
                logger.info(f"Sent notification for threat {instance.id}")
        except Exception as e:
            logger.error(f"Error sending notification: {e}")

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