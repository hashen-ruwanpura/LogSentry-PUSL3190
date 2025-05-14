# Create a new file: tasks.py
from celery import shared_task
from django.contrib.auth import get_user_model
from django.utils import timezone
import logging
from .notification_analytics import NotificationAnalytics

logger = logging.getLogger(__name__)
User = get_user_model()

def send_email_notification(email, alert_id):
    """Send an email notification using Django's email system"""
    from .models import Alert, EmailNotifier
    import logging
    
    logger = logging.getLogger(__name__)
    
    try:
        # Get the alert object
        alert = Alert.objects.get(id=alert_id)
        
        # Compose email subject and message
        subject = f"[{alert.severity.upper()}] Security Alert: {alert.type}"
        message = f"{alert.description}\n\n"
        
        if alert.ip_address:
            message += f"Source IP: {alert.ip_address}\n"
        
        if alert.affected_systems:
            message += f"Affected Systems: {alert.affected_systems}\n"
            
        if alert.mitre_tactics:
            message += f"\nMITRE ATT&CK Tactics: {alert.mitre_tactics}\n"
            
        if alert.recommendation:
            message += f"\nRecommended Action: {alert.recommendation}\n"
        
        # Send email
        result = EmailNotifier.send_alert(
            subject=subject,
            message=message,
            severity=alert.severity,
            recipients=[email],
            alert_id=alert.id,
            source_ip=alert.ip_address,
            affected_system=alert.affected_systems
        )
        
        # Record notification analytics
        if result:
            logger.info(f"Email notification sent to {email} for alert #{alert_id}")
        else:
            logger.error(f"Failed to send email notification to {email} for alert #{alert_id}")
            
        return result
        
    except Alert.DoesNotExist:
        logger.error(f"Cannot send email notification: Alert {alert_id} not found")
        return False
    except Exception as e:
        logger.error(f"Error sending email notification: {str(e)}")
        return False

def send_alert_notification_email(email, alert_id):
    """Send an alert notification email using Django's email system"""
    from django.core.mail import send_mail
    from django.conf import settings
    from .models import Alert
    
    try:
        # Get the alert
        alert = Alert.objects.get(id=alert_id)
        
        # Prepare email content
        subject = f"[{alert.severity.upper()}] Security Alert: {alert.type}"
        message = f"{alert.description}\n\n"
        
        if alert.ip_address:
            message += f"Source IP: {alert.ip_address}\n"
        
        if alert.affected_systems:
            message += f"Affected Systems: {alert.affected_systems}\n"
        
        # Use Django's send_mail which we know works
        result = send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False
        )
        
        return result > 0
    
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Error sending alert email: {e}")
        return False

@shared_task
def send_push_notification(user_id, alert_id):
    """Send push notification to user's devices"""
    from .models import Alert, PushNotificationService
    from authentication.models import UserDeviceToken
    
    try:
        # Get the user and alert
        user = User.objects.get(id=user_id)
        alert = Alert.objects.get(id=alert_id)
        
        # Get user's device tokens from UserDeviceToken model
        device_tokens = UserDeviceToken.objects.filter(
            user=user,
            is_active=True
        ).values_list('device_token', flat=True)
        
        # Skip if user has no device tokens
        if not device_tokens:
            logger.info(f"User {user.username} has no active device tokens for push notifications")
            return False
        
        # Compose notification
        title = f"{alert.severity.upper()}: {alert.type}"
        message = alert.description[:150] + ('...' if len(alert.description) > 150 else '')
        
        # Prepare data payload
        data = {
            'alert_id': str(alert.id),
            'severity': alert.severity,
            'type': alert.type,
            'source_ip': alert.ip_address or '',
            'affected_system': alert.affected_systems[:100] if alert.affected_systems else ''
        }
        
        # Send push notification
        push_service = PushNotificationService()
        result = push_service.send_notification(
            device_tokens=list(device_tokens),
            title=title,
            message=message,
            data=data
        )
        
        # Record analytics for each device
        if result:
            for token in device_tokens:
                device = UserDeviceToken.objects.get(device_token=token)
                device.last_used_at = timezone.now()
                device.save(update_fields=['last_used_at'])
                
                NotificationAnalytics.record_notification_sent(
                    notification_type='push',
                    alert_id=alert_id,
                    user_id=user_id
                )
            
        return result
    except User.DoesNotExist:
        logger.error(f"Cannot send push notification: User {user_id} not found")
        return False
    except Alert.DoesNotExist:
        logger.error(f"Cannot send push notification: Alert {alert_id} not found")
        return False
    except Exception as e:
        logger.error(f"Error sending push notification: {str(e)}")
        return False

@shared_task
def process_alert_notifications(alert_id):
    """Process all notifications for an alert asynchronously"""
    from .models import Alert
    from .notification_service import NotificationDispatcher
    
    try:
        alert = Alert.objects.get(id=alert_id)
        dispatcher = NotificationDispatcher()
        dispatcher.dispatch_alert(alert)
        logger.info(f"Successfully processed notifications for alert {alert_id}")
        return True
    except Alert.DoesNotExist:
        logger.error(f"Cannot process notifications: Alert {alert_id} not found")
        return False
    except Exception as e:
        logger.error(f"Error processing alert notifications: {str(e)}")
        return False