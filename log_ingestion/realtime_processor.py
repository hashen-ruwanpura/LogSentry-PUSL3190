import time
import threading
import logging
from django.utils import timezone
from django.conf import settings
from .models import LogSource, RawLog, ParsedLog
from .collectors import EnhancedLogCollectionManager
from threat_detection.rules import RuleEngine

logger = logging.getLogger(__name__)

class RealtimeLogProcessor:
    """
    A singleton class that manages continuous real-time log processing
    """
    _instance = None
    _lock = threading.Lock()
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
        
    def __init__(self):
        self.collection_manager = None
        self.rule_engine = RuleEngine()
        self.running = False
        self.thread = None
        self.last_processed_time = timezone.now()
        
    def start(self):
        """Start the real-time log processor"""
        if self.running:
            logger.info("Real-time log processor is already running")
            return False
            
        # Initialize log collection manager
        try:
            self.collection_manager = EnhancedLogCollectionManager()
            
            # Start monitoring logs
            observers, threads = self.collection_manager.start_monitoring()
            
            # Start the analysis thread
            self.running = True
            self.thread = threading.Thread(target=self._continuous_processing)
            self.thread.daemon = True
            self.thread.start()
            
            logger.info("Real-time log processor started successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to start real-time log processor: {str(e)}", exc_info=True)
            return False
    
    def stop(self):
        """Stop the real-time log processor"""
        if not self.running:
            return
            
        self.running = False
        if self.collection_manager:
            self.collection_manager.stop_monitoring()
        
        if self.thread:
            self.thread.join(timeout=5)
        
        logger.info("Real-time log processor stopped")
    
    def _continuous_processing(self):
        """Continuous log processing loop"""
        while self.running:
            try:
                # Find new unprocessed logs
                new_logs = RawLog.objects.filter(
                    is_parsed=False,
                    timestamp__gt=self.last_processed_time
                ).order_by('timestamp')[:100]  # Process in batches
                
                if new_logs.exists():
                    self.last_processed_time = new_logs.last().timestamp
                    
                    # Process each log
                    for raw_log in new_logs:
                        try:
                            # Get parser for this log type
                            from .parsers import LogParserFactory
                            parser = LogParserFactory.get_parser(raw_log.source.source_type)
                            
                            if parser:
                                # Parse the log
                                parsed_log = parser.parse(raw_log)
                                
                                # Analyze for threats (will be handled by signal handlers)
                                # The signal handlers in threat_detection/signals.py will take care of analysis
                                
                                logger.debug(f"Processed log ID {raw_log.id} successfully")
                            else:
                                logger.warning(f"No parser found for log type: {raw_log.source.source_type}")
                                raw_log.is_parsed = True
                                raw_log.save()
                        except Exception as e:
                            logger.error(f"Error processing log {raw_log.id}: {str(e)}")
                            # Mark as processed to avoid retry
                            raw_log.is_parsed = True
                            raw_log.save()
                
                # Sleep to avoid excessive CPU usage
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error in continuous processing: {str(e)}")
                time.sleep(5)  # Longer delay on error