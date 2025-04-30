from django.apps import AppConfig

class LogIngestionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'log_ingestion'

    def ready(self):
        # Import signal handlers
        import log_ingestion.signals
        
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
