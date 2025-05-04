import time
import threading
import logging
import os
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
            # Get log sources with validation
            log_sources = LogSource.objects.filter(enabled=True)
            
            # Check if we have any valid sources
            if not log_sources.exists():
                logger.warning("No enabled log sources found - creating defaults")
                # Create default sources before continuing
                self._create_default_sources()
                log_sources = LogSource.objects.filter(enabled=True)
            
            clean_log_files = []
            
            for source in log_sources:
                # Check for invalid paths
                if not source.file_path or source.file_path.strip() == "":
                    logger.warning(f"Skipping log source with empty path: {source.name}")
                    continue
                    
                # Clean and normalize the path
                clean_path = source.file_path.strip().strip('"\'')
                clean_path = os.path.normpath(clean_path)
                
                # Skip paths that are just '.' or have no directory component
                if clean_path == "." or os.path.dirname(clean_path) == "":
                    logger.warning(f"Invalid log path for {source.name}: {clean_path}")
                    continue
                
                # Update the source in database if needed
                if clean_path != source.file_path:
                    source.file_path = clean_path
                    source.save(update_fields=['file_path'])
                
                clean_log_files.append({
                    'path': clean_path,
                    'type': source.source_type
                })
            
            # Don't proceed if we have no valid log files
            if not clean_log_files:
                logger.error("No valid log files to monitor")
                return False
                
            # Create config dictionary based on available log sources
            config = {
                'use_filebeat': getattr(settings, 'USE_FILEBEAT', False),
                'filebeat_config': getattr(settings, 'FILEBEAT_CONFIG_PATH', 'config/filebeat.yml'),
                'log_files': clean_log_files
            }
            
            self.collection_manager = EnhancedLogCollectionManager(config)
            
            # Start monitoring logs
            observers, threads = self.collection_manager.start_monitoring()
            
            # Check if we got any observers
            if not observers:
                logger.warning("No log file observers were created")
                
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
        
    def _create_default_sources(self):
        """Create default log sources if none exist"""
        defaults = []
        
        try:
            # Default Apache log
            apache_path = r"C:\xampp\apache\logs\access.log" if os.name == 'nt' else "/var/log/apache2/access.log"
            apache_source, created = LogSource.objects.get_or_create(
                name="Apache Web Server",
                defaults={
                    'source_type': "apache",
                    'file_path': apache_path,
                    'enabled': True
                }
            )
            if created:
                defaults.append(apache_source)
                
            # Default MySQL log
            mysql_path = r"C:\xampp\mysql\data\mysql_error.log" if os.name == 'nt' else "/var/log/mysql/mysql.log"
            mysql_source, created = LogSource.objects.get_or_create(
                name="MySQL Database Server",
                defaults={
                    'source_type': "mysql",
                    'file_path': mysql_path,
                    'enabled': True
                }
            )
            if created:
                defaults.append(mysql_source)
                
            return defaults
        except Exception as e:
            logger.error(f"Error creating default log sources: {str(e)}")
            return []
    
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
    
    def restart(self):
        """Restart the log processor by stopping and starting it again."""
        try:
            # Stop the processor if it's running
            self.stop()
            
            # Brief delay to ensure clean shutdown
            time.sleep(1)  
            
            # Start again
            success = self.start()
            
            if success:
                logger.info("Log processor successfully restarted")
                return True
            else:
                logger.error("Failed to restart log processor")
                return False
        except Exception as e:
            logger.error(f"Error during log processor restart: {str(e)}", exc_info=True)
            return False
    
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