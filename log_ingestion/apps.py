from django.apps import AppConfig
import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

class LogIngestionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'log_ingestion'
    
    def ready(self):
        """Initialize the real-time log processor when the app is ready"""
        # Only run in the main thread, not during Django's auto-reloading
        if os.environ.get('RUN_MAIN') != 'true':
            # Start the processor in a separate thread with delay to ensure DB is ready
            threading.Thread(target=self._delayed_start, daemon=True).start()
    
    def _delayed_start(self):
        """Start the real-time processor with a delay to ensure DB is ready"""
        try:
            # Wait for the Django app to fully initialize
            time.sleep(5)
            
            # Now start the processor
            from log_ingestion.realtime_processor import RealtimeLogProcessor
            processor = RealtimeLogProcessor.get_instance()
            
            # Try to start it - this will use stored settings
            success = processor.start()
            
            if success:
                logger.info("Real-time log processor started successfully on app startup")
            else:
                logger.warning("Failed to start real-time log processor on app startup")
                
        except Exception as e:
            logger.error(f"Error starting real-time processor: {str(e)}", exc_info=True)
