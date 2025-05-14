from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Alert

@receiver(post_save, sender=Alert)
def alert_created_handler(sender, instance, created, **kwargs):
    """Trigger notifications when a new alert is created"""
    if created:
        # Instead of: process_alert_notifications.delay(instance.id)
        # Call directly:
        from .tasks import process_alert_notifications
        process_alert_notifications(instance.id)