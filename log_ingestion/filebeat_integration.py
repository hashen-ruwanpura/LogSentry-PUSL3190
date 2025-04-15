import subprocess
import os
import logging
import json
from threading import Thread
from kafka import KafkaConsumer
from .parsers import ApacheLogParser, MySQLLogParser
from .models import ParsedLog

logger = logging.getLogger(__name__)

class FilebeatManager:
    def __init__(self, config_path):
        self.config_path = config_path
        self.filebeat_process = None
        self.parsers = {
            'apache': ApacheLogParser(),
            'mysql': MySQLLogParser()
        }
    
    def start_filebeat(self):
        try:
            self.filebeat_process = subprocess.Popen(
                ["filebeat", "-c", self.config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            logger.info("Filebeat started successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to start Filebeat: {e}")
            return False
    
    def stop_filebeat(self):
        if self.filebeat_process:
            self.filebeat_process.terminate()
            self.filebeat_process.wait()
            logger.info("Filebeat stopped")
            
    def start_kafka_consumer(self):
        thread = Thread(target=self._consume_logs)
        thread.daemon = True
        thread.start()
        return thread
        
    def _consume_logs(self):
        consumer = KafkaConsumer(
            'raw_logs',
            bootstrap_servers='localhost:9092',
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset='latest',
            group_id='filebeat_consumer_group'
        )
        
        for message in consumer:
            log_data = message.value
            
            # Extract log type and content
            if isinstance(log_data, dict) and 'message' in log_data:
                content = log_data['message']
                source_file = log_data.get('log', {}).get('file', {}).get('path', '')
                
                # Determine parser type based on source file
                parser_type = 'apache' if 'apache' in source_file.lower() else 'mysql' if 'mysql' in source_file.lower() else None
                
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