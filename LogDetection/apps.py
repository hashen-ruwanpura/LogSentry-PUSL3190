# filepath: c:\Users\MSii\Desktop\Threat-Detection-and-Notification-Platform-by-Analyzing-Logs-of-Apache-and-MySQL-servers-\LogDetection\apps.py
from django.apps import AppConfig
import threading
import time
import logging

logger = logging.getLogger(__name__)

class LogMonitorThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)  # Daemon thread will exit when main thread exits
        self.running = True
        
    def run(self):
        while self.running:
            try:
                # Import here to avoid circular imports
                from log_ingestion.models import LogSource
                from threat_detection.services import analyze_logs
                
                # Process logs from configured sources
                sources = LogSource.objects.filter(enabled=True)
                if sources:
                    for source in sources:
                        analyze_logs(source)
                        
                # Sleep for interval (e.g., 30 seconds)
                time.sleep(30)
            except Exception as e:
                logger.error(f"Error in log monitoring thread: {str(e)}")
                time.sleep(60)  # Sleep longer if there was an error

class LogDetectionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'LogDetection'
    
    def ready(self):
        # Don't start thread when running management commands
        import sys
        if 'runserver' in sys.argv:
            # Start log monitoring thread
            LogMonitorThread().start()
            logger.info("Log monitoring thread started")