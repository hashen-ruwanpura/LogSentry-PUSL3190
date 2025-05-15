from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
import json
import logging

from log_ingestion.models import ParsedLog
from .models import Threat, Incident
from threat_detection.rules import RuleEngine
from .integrations import ThreatIntelligence
# Import our alert service
from alerts.services import AlertService

# Configure logger
logger = logging.getLogger(__name__)

@receiver(post_save, sender=ParsedLog)
def analyze_log_for_threats(sender, instance, created, **kwargs):
    """
    Enhanced signal handler that analyzes each newly saved ParsedLog for threats.
    This enables real-time threat detection as logs are parsed, with better pattern matching.
    """
    if created:  # Only process newly created logs
        try:
            # Check if the log has already been identified as suspicious in the parser
            if hasattr(instance, 'status') and instance.status in ('suspicious', 'attack'):
                logger.info(f"Pre-flagged suspicious log detected: {instance.id}, status: {instance.status}")
            
            # Initialize the rule engine for real-time threat detection
            rule_engine = RuleEngine()
            
            # Analyze the log for threats
            threats = rule_engine.analyze_log(instance)
            
            # If threats are detected, trigger notifications
            if threats:
                logger.warning(f"Detected {len(threats)} threats from log {instance.id}")
                
                # Extract threat details for alert
                threat_details = []
                severity = 'low'
                
                for threat in threats:
                    # Include each threat and find highest severity
                    threat_details.append(f"{threat.rule.name} ({threat.severity})")
                    
                    # Update overall severity to the highest
                    if threat.severity == 'critical':
                        severity = 'critical'
                    elif threat.severity == 'high' and severity not in ['critical']:
                        severity = 'high'
                    elif threat.severity == 'medium' and severity not in ['critical', 'high']:
                        severity = 'medium'
                
                # Format threat list for message
                threat_list = ', '.join(threat_details)
                
                # Build more detailed alert message
                title = f"Security threat detected from {instance.source_ip}"
                message = f"""
                Threat details:
                - IP Address: {instance.source_ip or 'Unknown'}
                - Timestamp: {instance.timestamp}
                - Path: {instance.request_path if hasattr(instance, 'request_path') and instance.request_path else 'N/A'}
                - Method: {instance.request_method if hasattr(instance, 'request_method') and instance.request_method else 'N/A'}
                - Status: {instance.status_code if hasattr(instance, 'status_code') and instance.status_code else 'N/A'}
                - User Agent: {instance.user_agent[:100] + '...' if hasattr(instance, 'user_agent') and instance.user_agent and len(instance.user_agent) > 100 else (instance.user_agent if hasattr(instance, 'user_agent') and instance.user_agent else 'N/A')}
                - Threat type: {threat_list}
                """
                
                # Send consolidated alert for all threats in this log
                # Use the first threat's ID as representative
                AlertService.send_alert(
                    title=title,
                    message=message,
                    severity=severity,
                    threat_id=threats[0].id if threats else None,  # Add threat_id
                    source_ip=instance.source_ip,
                    affected_system=instance.source_type if hasattr(instance, 'source_type') else None
                )
                
                # Also notify about each individual threat to ensure proper tracking
                for threat in threats:
                    # Check if this threat is part of a larger incident
                    check_for_incident(threat)
                
        except Exception as e:
            logger.error(f"Error in threat analysis signal handler: {e}", exc_info=True)

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
            # Only notify about medium and higher threats
            if instance.severity in ['medium', 'high', 'critical']:
                title = f"{instance.severity.upper()} Security Threat Detected"
                
                # Build message
                message = f"Description: {instance.description}\n"
                message += f"Source IP: {instance.source_ip or 'unknown'}\n"
                message += f"User: {instance.user_id or 'unknown'}\n"
                
                # Add reputation info if available
                if instance.analysis_data and 'threat_intelligence' in instance.analysis_data:
                    ti = instance.analysis_data['threat_intelligence']
                    if 'abuseipdb' in ti:
                        message += f"Reputation Score: {ti['abuseipdb']['score']}/100\n"
                    elif 'mock' in ti:
                        message += f"Reputation Score: {ti['mock']['score']}/100\n"

                # Add MITRE ATT&CK info if available
                if hasattr(instance, 'mitre_tactic') and instance.mitre_tactic:
                    message += f"MITRE ATT&CK Tactic: {instance.mitre_tactic}\n"
                
                # Send alert through our integrated service
                AlertService.send_alert(
                    title=title,
                    message=message,
                    severity=instance.severity,
                    threat_id=instance.id,
                    source_ip=instance.source_ip,
                    affected_system=instance.affected_system if hasattr(instance, 'affected_system') else None
                )
                
                logger.info(f"Alert notifications sent for threat {instance.id}")
        except Exception as e:
            logger.error(f"Error sending notifications: {e}")

# Enhanced version of the check_for_incident function
def check_for_incident(threat):
    """
    Enhanced incident correlation that analyzes attack patterns
    and groups related threats into security incidents.
    """
    # Skip if no source IP (can't correlate)
    if not threat.source_ip:
        return
        
    try:
        # Use a wider timeframe for better correlation
        recent_timeframe = timezone.now() - timezone.timedelta(hours=24)
        
        # Get recent threats from the same IP first
        related_by_ip = Threat.objects.filter(
            source_ip=threat.source_ip,
            created_at__gte=recent_timeframe
        ).exclude(id=threat.id).order_by('-created_at')
        
        # Also check for pattern-based relations (same rule/technique)
        if threat.rule_id:
            related_by_rule = Threat.objects.filter(
                rule_id=threat.rule_id,
                created_at__gte=recent_timeframe
            ).exclude(id=threat.id).order_by('-created_at')[:20]
        else:
            related_by_rule = Threat.objects.none()
            
        # Check for MITRE technique based relations
        if threat.mitre_technique:
            related_by_technique = Threat.objects.filter(
                mitre_technique=threat.mitre_technique,
                created_at__gte=recent_timeframe
            ).exclude(id=threat.id).order_by('-created_at')[:20]
        else:
            related_by_technique = Threat.objects.none()
            
        # Combine all related threats with no duplicates
        threat_ids = set()
        all_related = []
        
        # Add threats in order of relevance
        for t in list(related_by_ip) + list(related_by_rule) + list(related_by_technique):
            if t.id not in threat_ids:
                threat_ids.add(t.id)
                all_related.append(t)
                
        # If we have multiple threats, consider it an incident
        if len(all_related) >= 2:
            # First check if already part of an existing open incident
            existing_incident = None
            
            # Look for recent open incidents containing this threat or related threats
            for incident in Incident.objects.filter(
                status__in=['open', 'investigating'],
                start_time__gte=recent_timeframe
            ):
                incident_threats = incident.threats.all()
                
                # If this threat is already in the incident
                if threat in incident_threats:
                    existing_incident = incident
                    break
                    
                # If related threats are in this incident (at least 2)
                common_threats = sum(1 for t in all_related if t in incident_threats)
                if common_threats >= 2:
                    existing_incident = incident
                    break
            
            if existing_incident:
                # Update existing incident with new information
                # Add the current threat if not already included
                if threat not in existing_incident.threats.all():
                    existing_incident.threats.add(threat)
                
                # Add related threats not already included
                for related_threat in all_related:
                    if related_threat not in existing_incident.threats.all():
                        existing_incident.threats.add(related_threat)
                
                # Update incident metadata
                update_fields = []
                
                # Update severity if needed
                highest_severity = _get_highest_severity([threat] + all_related)
                if highest_severity != existing_incident.severity:
                    existing_incident.severity = highest_severity
                    update_fields.append('severity')
                
                # Update affected IPs and users
                affected_ips, affected_users = _get_affected_entities([threat] + all_related)
                
                if affected_ips:
                    existing_incident.affected_ips = json.dumps(list(affected_ips))
                    update_fields.append('affected_ips')
                    
                if affected_users:
                    existing_incident.affected_users = json.dumps(list(affected_users))
                    update_fields.append('affected_users')
                
                # Always update timestamp
                existing_incident.updated_at = timezone.now()
                update_fields.append('updated_at')
                
                if update_fields:
                    existing_incident.save(update_fields=update_fields)
                
                logger.info(f"Updated existing incident {existing_incident.id} with threat {threat.id}")
                
            else:
                # Create a new incident
                affected_ips, affected_users = _get_affected_entities([threat] + all_related)
                highest_severity = _get_highest_severity([threat] + all_related)
                
                # Determine incident type based on threats
                incident_type = _determine_incident_type([threat] + all_related)
                
                # Create incident name based on patterns
                if incident_type and threat.source_ip:
                    name = f"{incident_type} attack from {threat.source_ip}"
                elif incident_type:
                    name = f"{incident_type} attack detected"
                else:
                    name = f"Security incident from {threat.source_ip}" if threat.source_ip else "Security incident"
                
                # Create description with more details
                description = f"Multiple related security threats detected"
                
                if threat.source_ip:
                    description += f" from IP {threat.source_ip}"
                    
                if incident_type:
                    description += f". Attack type: {incident_type}"
                    
                if threat.mitre_technique:
                    description += f". MITRE ATT&CK Technique: {threat.mitre_technique}"
                
                incident = Incident.objects.create(
                    name=name,
                    description=description,
                    severity=highest_severity,
                    status='open',
                    start_time=min([t.created_at for t in [threat] + all_related]),
                    affected_ips=json.dumps(list(affected_ips)) if affected_ips else None,
                    affected_users=json.dumps(list(affected_users)) if affected_users else None
                )
                
                # Add all related threats
                incident.threats.add(threat, *all_related)
                
                logger.info(f"Created new incident {incident.id} with {incident.threats.count()} related threats")
    except Exception as e:
        logger.error(f"Error in check_for_incident: {e}", exc_info=True)

def _get_highest_severity(threats):
    """Determine highest severity from a list of threats"""
    severity_weights = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1
    }
    
    highest = 'low'
    highest_weight = 1
    
    for threat in threats:
        if severity_weights.get(threat.severity, 0) > highest_weight:
            highest = threat.severity
            highest_weight = severity_weights.get(threat.severity, 0)
            
    return highest

def _get_affected_entities(threats):
    """Extract unique IPs and users from threats"""
    affected_ips = set()
    affected_users = set()
    
    for threat in threats:
        if threat.source_ip:
            affected_ips.add(threat.source_ip)
        if threat.user_id:
            affected_users.add(threat.user_id)
            
    return affected_ips, affected_users

def _determine_incident_type(threats):
    """Determine the overall incident type based on threat patterns"""
    rule_types = {}
    mitre_tactics = {}
    
    for threat in threats:
        # Count rule types
        if threat.rule and threat.rule.rule_type:
            rule_type = threat.rule.rule_type
            rule_types[rule_type] = rule_types.get(rule_type, 0) + 1
            
        # Count MITRE tactics
        if threat.mitre_tactic:
            mitre_tactics[threat.mitre_tactic] = mitre_tactics.get(threat.mitre_tactic, 0) + 1
    
    # First try to determine by MITRE tactic (more standardized)
    if mitre_tactics:
        most_common_tactic = max(mitre_tactics.items(), key=lambda x: x[1])[0]
        return f"{most_common_tactic.replace('_', ' ').title()}"
        
    # Then try by rule type
    if rule_types:
        most_common_rule = max(rule_types.items(), key=lambda x: x[1])[0]
        return f"{most_common_rule.replace('Rule', '').replace('_', ' ').title()}"
        
    # Default
    return "Coordinated"

@receiver(post_save, sender=Incident)
def notify_about_incident(sender, instance, created, **kwargs):
    """Send notification about newly created or updated incidents"""
    try:
        # Only notify about new incidents or status changes
        if created or (kwargs.get('update_fields') and 'status' in kwargs.get('update_fields')):
            # Import AlertService
            from alerts.services import AlertService
            
            # Send incident notification
            AlertService.send_incident_notification(instance)
            
            logger.info(f"Incident notification sent for incident {instance.id}")
    except Exception as e:
        logger.error(f"Error sending incident notification: {e}", exc_info=True)