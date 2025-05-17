import os
import time
import logging
import re
from kafka import KafkaProducer, KafkaConsumer
import json
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from django.utils import timezone
from django.conf import settings
from .models import LogSource, LogFilePosition, RawLog
from .parsers import LogParserFactory, ApacheLogParser, MySQLLogParser
from .models import ParsedLog
from .filebeat_integration import FilebeatManager

logger = logging.getLogger(__name__)

class LogEventHandler(FileSystemEventHandler):
    def __init__(self, file_path, producer):
        self.file_path = file_path
        self.producer = producer
        self.last_position = self._get_file_size()
        
    def _get_file_size(self):
        return os.path.getsize(self.file_path) if os.path.exists(self.file_path) else 0
        
    def on_modified(self, event):
        if event.src_path == self.file_path:
            current_size = self._get_file_size()
            if current_size > self.last_position:
                with open(self.file_path, 'r') as f:
                    f.seek(self.last_position)
                    new_content = f.read()
                    for line in new_content.splitlines():
                        if line.strip():
                            # Send new log lines to Kafka topic
                            self.producer.send('raw_logs', {
                                'source': os.path.basename(self.file_path),
                                'content': line
                            })
                self.last_position = current_size

class LogFileHandler:
    def __init__(self, log_path, log_type):
        """Initialize log file handler with a path and log type"""
        # Clean up the log path - remove quotes and normalize
        self.log_path = log_path.strip().strip('"\'') if log_path else ""
        
        # Set default path if empty
        if not self.log_path:
            if os.name == 'nt':  # Windows
                if log_type == 'apache':
                    self.log_path = r"C:\xampp\apache\logs\access.log"
                else:
                    self.log_path = r"C:\xampp\mysql\data\mysql_error.log"
            else:  # Linux/Unix
                if log_type == 'apache':
                    self.log_path = "/var/log/apache2/access.log"
                else:
                    self.log_path = "/var/log/mysql/mysql.log"
                    
        # Normalize the path
        self.log_path = os.path.normpath(self.log_path)
        self.log_type = log_type
        
        # Ensure directory exists ONLY if it's a non-empty path
        log_dir = os.path.dirname(self.log_path)
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
                logger.info(f"Created directory: {log_dir}")
            except OSError as e:
                logger.warning(f"Could not create directory {log_dir}: {str(e)}")
    
    def start_monitoring(self):
        """Start monitoring this log file"""
        # Safety check for path
        if not self.log_path:
            logger.error("Cannot monitor empty log path")
            return None
            
        try:
            # Initialize Kafka producer with retry logic
            producer = KafkaProducer(
                bootstrap_servers='localhost:9092',
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                retries=3
            )
            
            # Create parent directory safely
            log_dir = os.path.dirname(self.log_path)
            if log_dir:
                try:
                    os.makedirs(log_dir, exist_ok=True)
                except OSError as e:
                    logger.error(f"Error creating directory {log_dir}: {str(e)}")
                    # Continue anyway, we'll try to monitor even if dir creation fails
            
            # Create the file if it doesn't exist
            if not os.path.exists(self.log_path):
                try:
                    with open(self.log_path, 'a'):
                        pass  # Just create an empty file
                    logger.info(f"Created log file: {self.log_path}")
                except Exception as e:
                    logger.error(f"Error creating log file: {str(e)}")
                    # Continue anyway
            
            # Create event handler and observer
            event_handler = LogEventHandler(self.log_path, producer)
            observer = Observer()
            observer.schedule(event_handler, path=os.path.dirname(self.log_path), recursive=False)
            observer.start()
            
            return observer
        except Exception as e:
            logger.error(f"Error starting log monitoring for {self.log_path}: {str(e)}")
            return None

class LogConsumer:
    def __init__(self):
        # Add retries and error handling for Kafka connection
        retry_count = 0
        max_retries = 3
        while retry_count < max_retries:
            try:
                self.consumer = KafkaConsumer(
                    'raw_logs',
                    bootstrap_servers='localhost:9092',
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                    auto_offset_reset='latest',
                    group_id='log_parser_group',
                    # Fix the timeout issue - make request_timeout larger than session_timeout
                    request_timeout_ms=12000,     # Increased from 5000 to 12000
                    session_timeout_ms=10000,     # Explicitly set session timeout 
                    # Add retry settings
                    retry_backoff_ms=1000,
                    reconnect_backoff_ms=1000
                )
                print("Successfully connected to Kafka")
                break
            except Exception as e:
                retry_count += 1
                print(f"Failed to connect to Kafka (attempt {retry_count}/{max_retries}): {e}")
                if retry_count >= max_retries:
                    print("Could not connect to Kafka, continuing without Kafka functionality")
                    self.consumer = None
                time.sleep(2)  # Wait before retrying

        self.parsers = {
            'apache': ApacheLogParser(),
            'mysql': MySQLLogParser()
        }
        
    def start_consuming(self):
        thread = threading.Thread(target=self._consume_logs)
        thread.daemon = True
        thread.start()
        return thread
        
    def _consume_logs(self):
        """Process incoming logs from Kafka topic"""
        if not self.consumer:
            logger.error("No Kafka consumer available")
            return
        
        success_count = 0
        last_log_time = time.time()
        
        try:
            for message in self.consumer:
                try:
                    # Get the raw message value - could be string or dict
                    log_data = message.value
                    
                    # Step 1: Extract content safely without accessing attributes
                    if isinstance(log_data, dict):
                        source = log_data.get('source', 'unknown')
                        content = log_data.get('content', '')
                    else:
                        # It's a string or something else - convert to string
                        source = 'unknown'
                        content = str(log_data)
                    
                    # Step 2: Determine parser type based on source/content
                    parser_type = None
                    if 'apache' in source.lower():
                        parser_type = 'apache'
                    elif 'mysql' in source.lower():
                        parser_type = 'mysql'
                    else:
                        # Try to guess based on content
                        if 'apache' in content.lower() or '[error]' in content.lower():
                            parser_type = 'apache'
                        elif 'mysql' in content.lower():
                            parser_type = 'mysql'
                    
                    # Step 3: Process with appropriate parser if available
                    if parser_type and parser_type in self.parsers:
                        parser = self.parsers[parser_type]
                        
                        # Always create a temporary wrapper object - never use raw strings
                        from django.utils import timezone
                        
                        class TempLog:
                            def __init__(self, content_str):
                                self.content = content_str
                                self.timestamp = timezone.now()
                        
                        # Parse using the wrapper - this is the key fix
                        temp_log = TempLog(content)
                        
                        # Pass the temp_log (not raw content) to the parser
                        parsed_result = parser.parse(temp_log)
                        
                        if parsed_result:
                            success_count += 1
                            
                            # Only log every 10 successes or after 5 seconds
                            current_time = time.time()
                            if success_count % 10 == 0 or (current_time - last_log_time) > 5:
                                logger.debug(f"Successfully parsed {parser_type} log from Kafka (count: {success_count})")
                                last_log_time = current_time
                                
                        else:
                            logger.warning(f"Failed to parse {parser_type} log from Kafka")
                    else:
                        logger.debug(f"No parser found for source: {source}")
                except Exception as e:
                    # More detailed error tracking
                    logger.error(f"Error processing Kafka message: {str(e)}")
                    import traceback
                    logger.debug(f"Details: {traceback.format_exc()}")
        except Exception as e:
            logger.error(f"Error in Kafka consumer: {str(e)}")

class LogCollectionManager:
    def __init__(self, config):
        self.config = config
        self.handlers = []
        self.observers = []
        self.consumer = LogConsumer()
        
    def start_monitoring(self):
        """Start monitoring all configured log files"""
        observers = []
        threads = []
        
        if not self.config.get('log_files'):
            logger.warning("No log files configured for monitoring")
            return observers, threads
        
        for log_config in self.config.get('log_files', []):
            try:
                # Validate and clean the config
                if not log_config or not isinstance(log_config, dict):
                    logger.warning(f"Invalid log configuration: {log_config}")
                    continue
                    
                # Get and validate path
                path = log_config.get('path', '').strip().strip('"\'')
                if not path:
                    logger.warning(f"Skipping log file with empty path: {log_config}")
                    continue
                
                # Normalize path and update config
                path = os.path.normpath(path)
                log_config['path'] = path
                
                # Get log type, default to 'apache'
                log_type = log_config.get('type', 'apache')
                
                logger.info(f"Setting up monitoring for {log_type} log at {path}")
                
                # Create handler with clean path
                handler = LogFileHandler(path, log_type)
                observer = handler.start_monitoring()
                
                if observer:  # Only add valid observers
                    self.handlers.append(handler)
                    observers.append(observer)
                
            except Exception as e:
                logger.error(f"Error setting up log monitoring for {log_config}: {str(e)}")
        
        # Start log consumer
        try:
            consumer_thread = self.consumer.start_consuming()
            threads.append(consumer_thread)
        except Exception as e:
            logger.error(f"Error starting log consumer: {str(e)}")
        
        return observers, threads
    
    def stop_monitoring(self):
        for observer in self.observers:
            observer.stop()
        
        for observer in self.observers:
            observer.join()

class EnhancedLogCollectionManager:
    """Enhanced version that supports both file monitoring and Filebeat"""
    def __init__(self, config):
        self.config = config
        self.handlers = []
        self.observers = []
        self.consumer = LogConsumer()
        
        # Initialize Filebeat if config specifies it
        self.use_filebeat = config.get('use_filebeat', False)
        if self.use_filebeat:
            from .filebeat_integration import FilebeatManager
            self.filebeat_manager = FilebeatManager(config.get('filebeat_config', 'config/filebeat.yml'))
        
    def start_monitoring(self):
        threads = []
        observers = []
        
        # Start Filebeat if configured
        if self.use_filebeat:
            self.filebeat_manager.start_filebeat()
            filebeat_consumer_thread = self.filebeat_manager.start_kafka_consumer()
            threads.append(filebeat_consumer_thread)
        
        # Also start traditional file monitoring for backward compatibility
        for log_config in self.config.get('log_files', []):
            try:
                # Skip invalid configurations
                if not isinstance(log_config, dict):
                    logger.warning(f"Skipping invalid log config (not a dict): {log_config}")
                    continue
                
                # Verify we have a valid path and type
                if 'path' not in log_config or not log_config['path']:
                    logger.warning("Skipping log config with missing path")
                    continue
                    
                # Clean and normalize the path, rejecting any that are just "."
                path = log_config['path'].strip().strip('"\'') if log_config['path'] else ""
                if not path or path == "." or os.path.dirname(path) == "":
                    logger.warning(f"Invalid log path: '{path}'. Must be a full file path.")
                    continue
                
                # Normalize and validate - ensure it's a file path not just a directory
                path = os.path.normpath(path)
                if os.path.isdir(path):
                    logger.warning(f"Path is a directory, not a file: {path}")
                    continue
                
                # Get log type, default to 'apache'
                log_type = log_config.get('type', 'apache')
                
                logger.info(f"Setting up monitoring for {log_type} log at {path}")
                
                # Create handler with clean path
                handler = LogFileHandler(path, log_type)
                observer = handler.start_monitoring()
                
                if observer:  # Only add valid observers
                    self.handlers.append(handler)
                    self.observers.append(observer)
                    observers.append(observer)
                
            except Exception as e:
                logger.error(f"Error setting up log monitoring for {log_config}: {str(e)}")
        
        # Start log consumer
        try:
            consumer_thread = self.consumer.start_consuming()
            threads.append(consumer_thread)
        except Exception as e:
            logger.error(f"Error starting log consumer: {str(e)}")
        
        return observers, threads
    
    def stop_monitoring(self):
        # Stop file observers
        for observer in self.observers:
            try:
                observer.stop()
            except Exception as e:
                logger.error(f"Error stopping observer: {str(e)}")
        
        for observer in self.observers:
            try:
                observer.join()
            except Exception as e:
                logger.error(f"Error joining observer thread: {str(e)}")
            
        # Stop Filebeat if used
        if self.use_filebeat:
            try:
                self.filebeat_manager.stop_filebeat()
            except Exception as e:
                logger.error(f"Error stopping filebeat: {str(e)}")

class MySQLLogPatternFilter:
    """Filter for identifying and handling repetitive MySQL error logs."""
    
    def __init__(self):
        # Patterns to identify common MySQL table definition errors
        self.known_error_patterns = [
            r"Incorrect definition of table mysql\.column_stats: expected column 'histogram'",
            r"Incorrect definition of table mysql\.column_stats: expected column 'hist_type'",
            # Add other common error patterns here
        ]
        
        # Track patterns and their occurrence counts
        self.pattern_counts = {}
        self.last_reset_time = time.time()
        self.reset_interval = 300  # Reset counts every 5 minutes
    
    def should_process_log(self, log_content):
        """
        Determine if a log should be processed based on pattern matching.
        Returns True if log should be processed, False if it should be filtered out.
        """
        # Check if we need to reset pattern counts
        current_time = time.time()
        if current_time - self.last_reset_time > self.reset_interval:
            self.pattern_counts = {}
            self.last_reset_time = current_time
        
        # Check against known patterns
        for pattern in self.known_error_patterns:
            if re.search(pattern, log_content):
                # Count occurrences of this pattern
                if pattern in self.pattern_counts:
                    self.pattern_counts[pattern] += 1
                    
                    # If we've seen this pattern too many times, filter it out
                    # Only process 1 out of every 100 repetitive errors
                    if self.pattern_counts[pattern] % 100 != 0:
                        return False
                else:
                    self.pattern_counts[pattern] = 1
                
                # Log this occurrence if it's the first or periodic
                if self.pattern_counts[pattern] == 1 or self.pattern_counts[pattern] % 100 == 0:
                    logger.debug(f"MySQL error pattern matched ({self.pattern_counts[pattern]} occurrences): {pattern}")
                    # Still process the first occurrence of each pattern
                    return True
                    
                return False
        
        # Not a known error pattern, process it
        return True
        
# Add this to the MySQL log collector in collectors.py

class MySQLLogCollector:
    def __init__(self):
        self.pattern_filter = MySQLLogPatternFilter()
        
    def process_line(self, line):
        # Skip if it matches a repetitive error pattern
        if not self.pattern_filter.should_process_log(line):
            return None
            
        # Continue with normal processing
        # [existing code]