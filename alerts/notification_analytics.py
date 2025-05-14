from django.utils import timezone
from .models import NotificationEvent

class NotificationAnalytics:
    """Track and analyze notification effectiveness"""
    
    @staticmethod
    def record_notification_sent(notification_type, alert_id, user_id):
        """Record that a notification was sent"""
        NotificationEvent.objects.create(
            event_type='sent',
            notification_type=notification_type,
            alert_id=alert_id,
            user_id=user_id,
            timestamp=timezone.now()
        )
    
    @staticmethod
    def record_notification_opened(notification_type, alert_id, user_id):
        """Record that a notification was opened"""
        NotificationEvent.objects.create(
            event_type='opened',
            notification_type=notification_type,
            alert_id=alert_id,
            user_id=user_id,
            timestamp=timezone.now()
        )
        
    @staticmethod
    def get_open_rates(days=30):
        """Calculate notification open rates by type"""
        end_date = timezone.now()
        start_date = end_date - timezone.timedelta(days=days)
        
        open_rates = {}
        
        for notification_type in ['email', 'push', 'in_app', 'sms']:
            sent_count = NotificationEvent.objects.filter(
                event_type='sent',
                notification_type=notification_type,
                timestamp__range=(start_date, end_date)
            ).count()
            
            opened_count = NotificationEvent.objects.filter(
                event_type='opened',
                notification_type=notification_type,
                timestamp__range=(start_date, end_date)
            ).count()
            
            if sent_count > 0:
                open_rates[notification_type] = (opened_count / sent_count) * 100
            else:
                open_rates[notification_type] = 0
                
        return open_rates