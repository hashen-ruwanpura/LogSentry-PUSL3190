from django.contrib.auth import get_user_model
from .models import Alert
from .tasks import process_alert_notifications
import logging

User = get_user_model()
logger = logging.getLogger(__name__)

def test_notification_system():
    """
    Test the notification system by creating a test alert and sending notifications
    
    Run this from Django shell:
    from alerts.test_notifications import test_notification_system; test_notification_system()
    """
    try:
        # Create a test alert
        alert = Alert.objects.create(
            type="intrusion",
            source="System Test",
            severity="medium",
            description="This is a test alert from the notification system verification script.",
            ip_address="192.168.1.100",
            affected_systems="Test System"
        )
        
        # Process notifications
        process_alert_notifications(alert.id)
        
        logger.info(f"Test notification sent for alert ID {alert.id}")
        return True, alert.id
    except Exception as e:
        logger.error(f"Failed to test notification system: {e}")
        return False, None