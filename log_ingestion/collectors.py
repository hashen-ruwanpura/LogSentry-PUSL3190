import os
import time
import logging
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
        self.log_path = log_path
        self.log_type = log_type
        
        # Fix: Ensure directory exists before monitoring
        log_dir = os.path.dirname(self.log_path)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            
        # Fix: Print paths for debugging
        print(f"Monitoring log file: {self.log_path}")
        print(f"Directory: {log_dir}")
        
        self.producer = KafkaProducer(
            bootstrap_servers='localhost:9092',
            value_serializer=lambda v: json.dumps(v).encode('utf-8')
        )
        
    def start_monitoring(self):
        import os
        print(f"Monitoring file: {self.log_path}")
        print(f"Directory exists: {os.path.exists(os.path.dirname(self.log_path))}")
        print(f"File exists: {os.path.exists(self.log_path)}")
        
        # Make sure directory exists
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        
        # Create an empty file if it doesn't exist
        if not os.path.exists(self.log_path):
            with open(self.log_path, 'w') as f:
                pass
        
        event_handler = LogEventHandler(self.log_path, self.producer)
        observer = Observer()
        observer.schedule(event_handler, path=os.path.dirname(self.log_path), recursive=False)
        observer.start()
        return observer
        
    def __del__(self):
        if hasattr(self, 'producer'):
            self.producer.close()

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
                    # Add connection timeout - don't wait too long
                    request_timeout_ms=5000,
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
        for message in self.consumer:
            log_data = message.value
            source = log_data['source']
            content = log_data['content']
            
            # Determine the parser based on the source filename
            parser_type = 'apache' if 'apache' in source.lower() else 'mysql' if 'mysql' in source.lower() else None
            
            if parser_type and parser_type in self.parsers:
                parser = self.parsers[parser_type]
                try:
                    parsed_log = parser.parse(content)
                    if parsed_log:
                        # Save parsed log to database
                        ParsedLog.objects.create(
                            log_type=parser_type,
                            source_ip=parsed_log.get('source_ip', ''),
                            timestamp=parsed_log.get('timestamp'),
                            http_method=parsed_log.get('http_method', ''),
                            path=parsed_log.get('path', ''),
                            status_code=parsed_log.get('status_code'),
                            user_agent=parsed_log.get('user_agent', ''),
                            raw_log=content
                        )
                except Exception as e:
                    logger.error(f"Error parsing log: {e}")

class LogCollectionManager:
    def __init__(self, config):
        self.config = config
        self.handlers = []
        self.observers = []
        self.consumer = LogConsumer()
        
    def start_monitoring(self):
        # Start log file watchers
        for log_config in self.config:
            handler = LogFileHandler(log_config['path'], log_config['type'])
            observer = handler.start_monitoring()
            self.handlers.append(handler)
            self.observers.append(observer)
        
        # Start log consumer
        consumer_thread = self.consumer.start_consuming()
        
        return self.observers, consumer_thread
    
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
        
        # Start Filebeat if configured
        if self.use_filebeat:
            self.filebeat_manager.start_filebeat()
            filebeat_consumer_thread = self.filebeat_manager.start_kafka_consumer()
            threads.append(filebeat_consumer_thread)
        
        # Also start traditional file monitoring for backward compatibility
        for log_config in self.config.get('log_files', []):
            handler = LogFileHandler(log_config['path'], log_config['type'])
            observer = handler.start_monitoring()
            self.handlers.append(handler)
            self.observers.append(observer)
        
        # Start log consumer
        consumer_thread = self.consumer.start_consuming()
        threads.append(consumer_thread)
        
        return self.observers, threads
    
    def stop_monitoring(self):
        # Stop file observers
        for observer in self.observers:
            observer.stop()
        
        for observer in self.observers:
            observer.join()
            
        # Stop Filebeat if used
        if self.use_filebeat:
            self.filebeat_manager.stop_filebeat()