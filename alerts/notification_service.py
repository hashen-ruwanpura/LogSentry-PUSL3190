from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.conf import settings
from django.contrib.auth import get_user_model
import json
import logging
from .models import (
    Alert, AlertNotification, NotificationPreference, 
    EmailNotifier, PushNotificationService, SlackNotifier
)
from .notification_analytics import NotificationAnalytics

User = get_user_model()
logger = logging.getLogger(__name__)

class NotificationService:
    """Notification service for sending alerts to users"""
    
    @staticmethod
    def send_alert(user_id, alert_data):
        """Send alert to user via WebSocket and other notification methods"""
        try:
            # Log this attempt
            logger.info(f"Sending notification to user {user_id}: {alert_data}")
            
            # Try to send via WebSocket
            channel_layer = get_channel_layer()
            user_group_name = f"notifications_{user_id}"
            
            # Send WebSocket notification
            try:
                async_to_sync(channel_layer.group_send)(
                    user_group_name,
                    {
                        'type': 'notification_alert',
                        'notification': alert_data
                    }
                )
                logger.info(f"WebSocket notification sent to user {user_id}")
            except Exception as e:
                logger.error(f"WebSocket notification failed: {e}")
                # WebSocket failed, notification will be delivered by polling
                
            # Record the notification in analytics
            NotificationAnalytics.record_notification_sent(
                notification_type='in_app',
                alert_id=alert_data.get('threat_id'),
                user_id=user_id
            )
            
            return True
        except Exception as e:
            logger.error(f"Error sending notification to user {user_id}: {str(e)}")
            return False
        
    @staticmethod
    def broadcast_critical_alert(alert_data):
        """Broadcast critical alert to all admin users"""
        channel_layer = get_channel_layer()
        try:
            async_to_sync(channel_layer.group_send)(
                "admin_notifications",
                {
                    'type': 'alert_notification',
                    'alert': alert_data
                }
            )
            return True
        except Exception as e:
            logger.error(f"Error broadcasting critical alert: {str(e)}")
            return False


class NotificationDispatcher:
    """Central service to handle all types of notifications"""
    
    def __init__(self):
        self.websocket_service = NotificationService()
        self.email_notifier = EmailNotifier()
        self.push_notifier = PushNotificationService()
        
        # Initialize Slack notifier if configured
        self.slack_notifier = None
        if hasattr(settings, 'SLACK_WEBHOOK_URL') and settings.SLACK_WEBHOOK_URL:
            self.slack_notifier = SlackNotifier()
        
    def _get_user_preferences(self, user):
        """Get notification preferences for a user"""
        try:
            return NotificationPreference.objects.get(user=user)
        except NotificationPreference.DoesNotExist:
            # Create default preferences if they don't exist
            return NotificationPreference.objects.create(user=user)
    
    def _should_send_email(self, alert, prefs):
        """Check if an email should be sent based on alert severity and user preferences"""
        if not prefs.email_alerts:
            return False
            
        alert_level = NotificationPreference.get_severity_level(alert.severity)
        pref_level = NotificationPreference.get_severity_level(prefs.email_threshold)
        
        return alert_level >= pref_level
    
    def _should_send_in_app(self, alert, prefs):
        """Check if an in-app notification should be sent"""
        if not prefs.in_app_alerts:
            return False
            
        alert_level = NotificationPreference.get_severity_level(alert.severity)
        pref_level = NotificationPreference.get_severity_level(prefs.in_app_threshold)
        
        return alert_level >= pref_level
    
    def _should_send_push(self, alert, prefs):
        """Check if a push notification should be sent"""
        if not prefs.push_alerts:
            return False
            
        alert_level = NotificationPreference.get_severity_level(alert.severity)
        pref_level = NotificationPreference.get_severity_level(prefs.push_threshold)
        
        return alert_level >= pref_level
    
    def _create_in_app_notification(self, user, alert):
        """Create an in-app notification for a user"""
        try:
            notification = AlertNotification.objects.create(
                user=user,
                title=f"{alert.severity.upper()}: {alert.type}",
                message=alert.description[:255],
                severity=alert.severity,
                threat_id=alert.id,
                source_ip=alert.ip_address,
                affected_system=alert.affected_systems[:100] if alert.affected_systems else None
            )
            
            # Send via WebSocket for real-time update
            alert_data = {
                'id': notification.id,
                'title': notification.title,
                'message': notification.message,
                'severity': notification.severity,
                'threat_id': notification.threat_id,
                'source_ip': notification.source_ip,
                'affected_system': notification.affected_system,
                'timestamp': notification.created_at.isoformat()
            }
            
            self.websocket_service.send_alert(user.id, alert_data)
            
            # If it's critical, also broadcast to admins
            if alert.severity == 'critical':
                self.websocket_service.broadcast_critical_alert(alert_data)
                
            return notification
        except Exception as e:
            logger.error(f"Error creating in-app notification: {str(e)}")
            return None
    
    def dispatch_alert(self, alert, users=None):
        """Dispatch alert to all configured channels based on user preferences"""
        if alert is None:
            logger.error("Cannot dispatch None alert")
            return
            
        if users is None:
            # Get all active users if not specified
            users = User.objects.filter(is_active=True)
            
        critical = alert.severity == 'critical'
        logger_prefix = "[CRITICAL ALERT]" if critical else "[ALERT]"
        
        logger.info(f"{logger_prefix} Dispatching alert ID #{alert.id} to {len(users)} users")
        
        for user in users:
            try:
                prefs = self._get_user_preferences(user)
                
                # In-app notifications
                if self._should_send_in_app(alert, prefs):
                    self._create_in_app_notification(user, alert)
                
                # Email notifications - check if we should send based on preferences
                if self._should_send_email(alert, prefs) and user.email:
                    logger.info(f"Sending email notification to {user.email} for alert {alert.id}")
                    # Use delay() if using Celery, otherwise call directly
                    try:
                        from .tasks import send_email_notification
                        send_email_notification(user.email, alert.id)
                        # Alternatively with Celery: send_email_notification.delay(user.email, alert.id)
                    except ImportError:
                        # Fall back to direct sending if tasks module isn't available
                        from .models import EmailNotifier
                        subject = f"[{alert.severity.upper()}] Security Alert: {alert.type}"
                        message = alert.description
                        EmailNotifier.send_alert(
                            subject=subject, 
                            message=message, 
                            severity=alert.severity,
                            recipients=[user.email],
                            alert_id=alert.id,
                            source_ip=alert.ip_address,
                            affected_system=alert.affected_systems
                        )
                
                # Push notifications if user has device tokens
                if self._should_send_push(alert, prefs) and hasattr(user, 'device_tokens'):
                    from .tasks import send_push_notification
                    send_push_notification(user.id, alert.id)
                    # With Celery: send_push_notification.delay(user.id, alert.id)
                    
            except Exception as e:
                logger.error(f"Error processing notifications for user {user.username}: {str(e)}")
        
        # Always notify Slack for critical alerts if configured
        if critical and self.slack_notifier:
            try:
                self.slack_notifier.send_alert(alert)
            except Exception as e:
                logger.error(f"Error sending Slack notification: {str(e)}")