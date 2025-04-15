import logging
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import ParsedLog, RawLog
from analytics.utils import convert_log_to_report

logger = logging.getLogger(__name__)

@receiver(post_save, sender=ParsedLog)
def process_parsed_log(sender, instance, created, **kwargs):
    """
    Signal handler that processes each newly saved ParsedLog and generates a report.
    This enables real-time reporting as logs are parsed.
    """
    if created:  # Only process newly created logs
        try:
            logger.info(f"Processing parsed log ID {instance.id} for reporting")
            # Convert the single parsed log to a report entry
            convert_log_to_report(instance)
        except Exception as e:
            logger.error(f"Error generating report from log {instance.id}: {e}")