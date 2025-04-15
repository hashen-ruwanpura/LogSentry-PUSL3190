from django.apps import AppConfig


class LogIngestionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'log_ingestion'
    
    def ready(self):
        # Import signals to register them
        from . import signals
