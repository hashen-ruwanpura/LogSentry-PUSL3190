from django.apps import AppConfig
import logging
import os
import sys

logger = logging.getLogger(__name__)

class LogIngestionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'log_ingestion'

    def ready(self):
        # Import signal handlers
        import log_ingestion.signals
        
        # Check if we're running the main Django process (not a reloader)
        # This prevents starting duplicate processes when using auto-reload in development
        if os.environ.get('RUN_MAIN', None) != 'true' and 'runserver' in sys.argv:
            logger.info("Django main process detected - initializing services")
            
            # Start Kafka and ZooKeeper
            from .kafka_manager import start_kafka_services
            start_kafka_services()
            
            # Start the real-time log processor if enabled
            from django.conf import settings
            if getattr(settings, 'ENABLE_REALTIME_LOG_PROCESSING', False) and not getattr(settings, 'TESTING', False):
                # Start in a separate thread to avoid blocking app startup
                import threading
                from .realtime_processor import RealtimeLogProcessor
                
                def start_processor():
                    processor = RealtimeLogProcessor.get_instance()
                    processor.start()
                
                # Start after a short delay to ensure the app is fully loaded
                timer = threading.Timer(5.0, start_processor)
                timer.daemon = True
                timer.start()
