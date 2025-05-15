import logging
from django.contrib.auth.models import User
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import AlertNotification, NotificationPreference, EmailNotifier
from django.utils import timezone
from django.db import transaction

logger = logging.getLogger(__name__)
channel_layer = get_channel_layer()

# --- NOTIFICATION SERVICES ---

# Purpose: Core service for sending alerts through multiple channels
# Usage: Called by threat detection engine when new threats are detected
# Related Frontend: Affects notifications.html, dashboard alerts, and email notifications
class AlertService:
    """Service class for handling alerts through multiple notification channels"""
    
    # Define severity colors for consistency
    SEVERITY_STYLES = {
        'critical': {'color': '#dc3545', 'icon': 'fa-skull-crossbones', 'sound': True},
        'high': {'color': '#fd7e14', 'icon': 'fa-exclamation-circle', 'sound': True},
        'medium': {'color': '#ffc107', 'icon': 'fa-exclamation-triangle', 'sound': False},
        'low': {'color': '#17a2b8', 'icon': 'fa-info-circle', 'sound': False},
    }
    
    @classmethod
    def send_alert(cls, title, message, severity, threat_id=None, source_ip=None, affected_system=None):
        """Send alert through multiple notification channels based on severity"""
        try:
            # Get style info based on severity
            style_info = cls.SEVERITY_STYLES.get(severity, {
                'color': '#17a2b8',
                'icon': 'fa-info-circle',
                'sound': False
            })
            
            # Construct alert data for WebSocket
            alert_data = {
                'title': title,
                'message': message,
                'severity': severity,
                'threat_id': threat_id,
                'source_ip': source_ip,
                'affected_system': affected_system,
                'timestamp': timezone.now().isoformat(),
                'color': style_info['color'],
                'icon': style_info['icon'],
                'play_sound': style_info['sound']
            }
            
            # Execute notification strategies based on severity
            results = []
            
            # 1. Send to appropriate admins via email based on severity
            results.append(cls._send_admin_email_alerts(
                title, message, severity, threat_id, source_ip, affected_system
            ))
            
            # 2. Create in-app notifications for relevant users
            results.append(cls._create_in_app_notifications(
                title, message, severity, threat_id, source_ip, affected_system
            ))
            
            # 3. Send real-time WebSocket notifications
            results.append(cls._send_websocket_notifications(alert_data, severity))
            
            # 4. Send push notifications if enabled and severe enough
            if severity in ['high', 'critical']:
                results.append(cls._send_push_notifications(
                    title, message, severity, threat_id, source_ip, affected_system
                ))
            
            # Log notification attempt
            logger.info(
                f"Alert notifications sent - Severity: {severity}, "
                f"Email: {results[0]}, In-App: {results[1]}, WebSocket: {results[2]}"
            )
            
            return True
        except Exception as e:
            logger.error(f"Error sending alert: {e}", exc_info=True)
            return False
    
    @classmethod
    def _send_admin_email_alerts(cls, title, message, severity, threat_id=None, source_ip=None, affected_system=None):
        """Send email alerts to admins based on severity threshold and prevent duplicates"""
        try:
            from django.contrib.auth.models import User
            from .models import NotificationPreference, EmailNotifier, EmailAlert
            from django.utils import timezone
            from django.db.models import Q
            
            # Check for duplicates if threat_id is provided
            if threat_id:
                # Don't send email if we've already sent an alert for this threat in the last hour
                one_hour_ago = timezone.now() - timezone.timedelta(hours=1)
                existing_alerts = EmailAlert.objects.filter(
                    Q(related_alert_id=threat_id) & 
                    Q(created_at__gte=one_hour_ago) &
                    Q(status='sent')
                )
                
                if existing_alerts.exists():
                    logger.info(f"Skipping email for threat {threat_id} - already sent within the last hour")
                    return False
            
            # Find admin users with email addresses who have enabled email alerts
            recipients = []
            
            # Get all users with staff status who have email addresses
            admin_users = User.objects.filter(is_staff=True, email__isnull=False).exclude(email='')
            
            for admin in admin_users:
                try:
                    # Check if admin has notification preferences
                    prefs = NotificationPreference.objects.get(user=admin)
                    
                    # Only send if email alerts are enabled and severity meets threshold
                    if prefs.email_alerts:
                        severity_level = NotificationPreference.get_severity_level(severity)
                        threshold_level = NotificationPreference.get_severity_level(prefs.email_threshold)
                        
                        # Send alert if severity is at or above threshold
                        if severity_level >= threshold_level:
                            recipients.append(admin.email)
                            
                except NotificationPreference.DoesNotExist:
                    # Default to sending emails for high/critical to admins without preferences
                    if severity in ['high', 'critical']:
                        recipients.append(admin.email)
            
            # Log recipient count
            recipient_str = ", ".join(recipients) if recipients else "none"
            logger.info(f"Sending {severity} alert email to {len(recipients)} recipients: {recipient_str}")
            
            # Send emails if there are recipients
            if recipients:
                # Create an email alert record to prevent duplicates
                email_alert = EmailAlert.objects.create(
                    subject=f"[{severity.upper()}] {title}",
                    message=message,
                    recipient=",".join(recipients),
                    severity=severity,
                    related_alert_id=threat_id,
                    status='pending',
                    created_at=timezone.now()
                )
                
                # Send the actual email
                success = EmailNotifier.send_alert(
                    subject=f"[{severity.upper()}] {title}",
                    message=message,
                    severity=severity,
                    recipients=recipients,
                    alert_id=threat_id,
                    source_ip=source_ip,
                    affected_system=affected_system
                )
                
                # Update the status
                if success:
                    email_alert.status = 'sent'
                    email_alert.sent_at = timezone.now()
                else:
                    email_alert.status = 'failed'
                    email_alert.error_message = "Failed to send email"
                    
                email_alert.save()
                return success
                
            return False
        except Exception as e:
            logger.error(f"Error sending admin email alerts: {e}", exc_info=True)
            return False
    
    @classmethod
    def _create_in_app_notifications(cls, title, message, severity, alert_id=None, source_ip=None, affected_system=None):
        """Create in-app notifications for relevant users"""
        try:
            with transaction.atomic():
                # Create notifications for users based on severity preference
                severity_level = NotificationPreference.get_severity_level(severity)
                eligible_users = User.objects.filter(
                    notificationpreference__in_app_alerts=True,
                ).exclude(
                    notificationpreference__in_app_threshold__in=['low', 'medium', 'high', 'critical'][:severity_level]
                )
                
                notifications = []
                for user in eligible_users:
                    notification = AlertNotification(
                        user=user,
                        title=title,
                        message=message,
                        severity=severity,
                        threat_id=alert_id,
                        source_ip=source_ip,
                        affected_system=affected_system
                    )
                    notifications.append(notification)
                
                # Bulk create the notifications
                if notifications:
                    AlertNotification.objects.bulk_create(notifications)
                    logger.info(f"In-app notifications created for {len(notifications)} users")
                    return True
                return False
        except Exception as e:
            logger.error(f"Error creating in-app notifications: {e}", exc_info=True)
            return False
    
    @classmethod
    def _send_websocket_notifications(cls, alert_data, severity):
        """Send WebSocket notifications to connected clients"""
        try:
            # Send to severity-based group (for admins monitoring by severity)
            async_to_sync(channel_layer.group_send)(
                f"severity_{severity}_alerts",
                {
                    'type': 'alert_notification',
                    'alert': alert_data
                }
            )
            
            # Get users who should receive this alert based on their preferences
            severity_level = NotificationPreference.get_severity_level(severity)
            eligible_user_ids = User.objects.filter(
                is_staff=True  # Only target staff users for now to ensure someone gets the alerts
            ).values_list('id', flat=True)
            
            # Send to each eligible user's group
            for user_id in eligible_user_ids:
                try:
                    # Use both legacy format (for backward compatibility) and new format
                    legacy_group = f"user_{user_id}_alerts"
                    new_group = f"notifications_{user_id}"
                    
                    # Send to both possible group formats to ensure delivery
                    async_to_sync(channel_layer.group_send)(
                        legacy_group,
                        {
                            'type': 'alert_notification',
                            'alert': alert_data
                        }
                    )
                    
                    async_to_sync(channel_layer.group_send)(
                        new_group,
                        {
                            'type': 'notification_alert',
                            'notification': alert_data
                        }
                    )
                except Exception as group_error:
                    logger.warning(f"Error sending to WebSocket group for user {user_id}: {group_error}")
                    
            logger.info(f"WebSocket notifications sent to {len(eligible_user_ids)} user groups")
            return True
        except Exception as e:
            logger.error(f"Error sending WebSocket notifications: {e}", exc_info=True)
            return False
            
    @classmethod
    def _send_push_notifications(cls, title, message, severity, alert_id=None, source_ip=None, affected_system=None):
        """Send push notifications to user devices"""
        try:
            # Import here to avoid circular import
            from .web_push import PushNotifier
            
            # Get users who should receive push notifications based on severity
            severity_level = NotificationPreference.get_severity_level(severity)
            eligible_users = User.objects.filter(
                notificationpreference__push_alerts=True,
            ).exclude(
                notificationpreference__push_threshold__in=['low', 'medium', 'high', 'critical'][:severity_level]
            )
            
            success_count = 0
            for user in eligible_users:
                # Create notification data
                data = {
                    'severity': severity,
                    'source_ip': source_ip or '',
                    'affected_system': affected_system or '',
                    'timestamp': timezone.now().isoformat()
                }
                
                # Send push notification
                if PushNotifier.send_to_user(user, title, message, data, severity, alert_id):
                    success_count += 1
                    
            if success_count > 0:
                logger.info(f"Push notifications sent to {success_count}/{len(eligible_users)} users")
                return True
            else:
                logger.info("No push notifications were successfully sent")
                return False
                
        except Exception as e:
            logger.error(f"Error sending push notifications: {e}", exc_info=True)
            return False

    @classmethod
    def send_incident_notification(cls, incident):
        """
        Send notifications about a security incident
        
        Args:
            incident: The Incident object
        """
        try:
            # 1. Send email notification
            from .models import EmailNotifier
            
            # Get admin users that should receive incident notifications
            admin_emails = User.objects.filter(
                is_staff=True, 
                notificationpreference__email_alerts=True
            ).values_list('email', flat=True)
            
            email_success = EmailNotifier.send_incident_notification(incident, list(admin_emails))
            
            # 2. Create in-app notifications for admins
            in_app_success = cls._create_incident_in_app_notifications(incident)
            
            # 3. Send WebSocket notifications
            ws_success = cls._send_incident_websocket_notification(incident)
            
            logger.info(f"Incident '{incident.name}' notification status: Email={email_success}, InApp={in_app_success}, WebSocket={ws_success}")
            
            return email_success or in_app_success or ws_success
            
        except Exception as e:
            logger.error(f"Error sending incident notification: {e}", exc_info=True)
            return False
    
    @classmethod        
    def _create_incident_in_app_notifications(cls, incident):
        """Create in-app notifications for the incident"""
        try:
            # Create notifications for all admins
            admin_users = User.objects.filter(is_staff=True)
            
            notifications = []
            for user in admin_users:
                notification = AlertNotification(
                    user=user,
                    title=f"Security Incident: {incident.name}",
                    message=f"{incident.description}\n\nStatus: {incident.status}",
                    severity=incident.severity,
                    affected_system=incident.affected_ips
                )
                notifications.append(notification)
            
            # Bulk create the notifications
            if notifications:
                AlertNotification.objects.bulk_create(notifications)
                return True
            return False
        except Exception as e:
            logger.error(f"Error creating incident in-app notifications: {e}", exc_info=True)
            return False
            
    @classmethod
    def _send_incident_websocket_notification(cls, incident):
        """Send WebSocket notification about the incident"""
        try:
            # Format incident data
            incident_data = {
                'type': 'incident',
                'id': incident.id,
                'name': incident.name,
                'description': incident.description,
                'severity': incident.severity,
                'status': incident.status,
                'timestamp': timezone.now().isoformat(),
                'affected_systems': incident.affected_ips
            }
            
            # Send to all admin users
            admin_ids = User.objects.filter(is_staff=True).values_list('id', flat=True)
            
            for user_id in admin_ids:
                async_to_sync(channel_layer.group_send)(
                    f"user_{user_id}_alerts",
                    {
                        'type': 'alert_notification',
                        'alert': incident_data
                    }
                )
            
            return True
        except Exception as e:
            logger.error(f"Error sending incident WebSocket notification: {e}", exc_info=True)
            return False