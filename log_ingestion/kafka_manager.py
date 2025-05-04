import subprocess
import os
import time
import logging
import socket
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

class KafkaManager:
    """Manages Kafka and ZooKeeper processes"""
    _instance = None
    _lock = threading.Lock()
    
    def __init__(self):
        self.zookeeper_process = None
        self.kafka_process = None
        self.is_running = False
        
        # Get KAFKA_HOME from settings
        from django.conf import settings
        self.KAFKA_HOME = getattr(settings, 'KAFKA_HOME', r"C:\Kafka_2.13-3.8.1")
        self.KAFKA_TOPICS = getattr(settings, 'KAFKA_TOPICS', ['raw_logs', 'apache_logs', 'mysql_logs'])
    
    @classmethod
    def get_instance(cls):
        """Get the singleton instance"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
    
    def _is_port_in_use(self, port):
        """Check if a port is in use"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0
            
    def is_zookeeper_running(self):
        """Check if ZooKeeper is running"""
        return self._is_port_in_use(2181)
        
    def is_kafka_running(self):
        """Check if Kafka is running"""
        return self._is_port_in_use(9092)
    
    def ensure_kafka_directories(self):
        """Ensure Kafka log directories exist"""
        try:
            kafka_logs_dir = os.path.join(self.KAFKA_HOME, "logs", "kafka-logs")
            zk_logs_dir = os.path.join(self.KAFKA_HOME, "logs", "zookeeper")
            
            os.makedirs(kafka_logs_dir, exist_ok=True)
            os.makedirs(zk_logs_dir, exist_ok=True)
            logger.info(f"Created Kafka log directories in {self.KAFKA_HOME}")
            return True
        except Exception as e:
            logger.error(f"Error creating Kafka log directories: {e}")
            return False
    
    def start_zookeeper(self):
        """Start ZooKeeper if not already running"""
        if self.is_zookeeper_running():
            logger.info("ZooKeeper is already running")
            return True
            
        try:
            logger.info("Starting ZooKeeper...")
            zk_script = os.path.join(self.KAFKA_HOME, "bin", "windows", "zookeeper-server-start.bat")
            zk_config = os.path.join(self.KAFKA_HOME, "config", "zookeeper.properties")
            
            # Fix: Use shell=True and direct command string with 'start' to open in new window
            command = f'start cmd /k "cd /d {self.KAFKA_HOME} && {zk_script} {zk_config}"'
            subprocess.Popen(command, shell=True)
            
            # Wait for ZooKeeper to start
            attempts = 0
            while attempts < 10:
                if self.is_zookeeper_running():
                    logger.info("ZooKeeper started successfully")
                    return True
                time.sleep(2)
                attempts += 1
                
            logger.error("Failed to start ZooKeeper after waiting")
            return False
        except Exception as e:
            logger.error(f"Error starting ZooKeeper: {e}")
            return False
    
    def start_kafka(self):
        """Start Kafka if not already running"""
        if self.is_kafka_running():
            logger.info("Kafka is already running")
            return True
            
        try:
            # Make sure ZooKeeper is running first
            if not self.is_zookeeper_running():
                if not self.start_zookeeper():
                    return False
            
            # Wait a bit longer for ZooKeeper to fully initialize
            time.sleep(5)
                    
            logger.info("Starting Kafka...")
            kafka_script = os.path.join(self.KAFKA_HOME, "bin", "windows", "kafka-server-start.bat")
            kafka_config = os.path.join(self.KAFKA_HOME, "config", "server.properties")
            
            # Fix: Use shell=True and direct command string with 'start' to open in new window
            command = f'start cmd /k "cd /d {self.KAFKA_HOME} && {kafka_script} {kafka_config}"'
            subprocess.Popen(command, shell=True)
            
            # Wait for Kafka to start with longer timeout
            attempts = 0
            while attempts < 20:  # Increased attempts
                if self.is_kafka_running():
                    logger.info("Kafka started successfully")
                    return True
                time.sleep(3)  # Increased sleep time
                attempts += 1
                logger.info(f"Waiting for Kafka to start (attempt {attempts}/20)...")
                
            logger.error("Failed to start Kafka after waiting")
            return False
        except Exception as e:
            logger.error(f"Error starting Kafka: {e}")
            return False
    
    def ensure_topics_exist(self):
        """Ensure all required Kafka topics exist"""
        if not self.is_kafka_running():
            logger.error("Kafka is not running. Cannot create topics.")
            return False
            
        try:
            success = True
            for topic in self.KAFKA_TOPICS:
                logger.info(f"Ensuring Kafka topic exists: {topic}")
                topic_script = os.path.join(self.KAFKA_HOME, "bin", "windows", "kafka-topics.bat")
                
                try:
                    # The --if-not-exists flag ensures we don't get an error if the topic already exists
                    result = subprocess.run([
                        topic_script,
                        "--create",
                        "--topic", topic,
                        "--bootstrap-server", "localhost:9092",
                        "--partitions", "3",
                        "--replication-factor", "1",
                        "--if-not-exists"
                    ], check=False, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                    
                    if result.returncode != 0:
                        error_msg = result.stderr.decode() if result.stderr else "Unknown error"
                        if "already exists" in error_msg:
                            logger.info(f"Topic {topic} already exists")
                        else:
                            logger.error(f"Error creating topic {topic}: {error_msg}")
                            success = False
                    else:
                        logger.info(f"Topic {topic} created/verified successfully")
                
                except Exception as e:
                    logger.error(f"Error creating Kafka topic {topic}: {e}")
                    success = False
            
            return success
        except Exception as e:
            logger.error(f"Unexpected error creating Kafka topics: {e}")
            return False
    
    def start_all(self):
        """Start ZooKeeper, Kafka, and ensure topics exist"""
        if self.is_running:
            logger.info("Kafka services are already started")
            return True
            
        try:
            if not self.ensure_kafka_directories():
                return False
                
            if not self.start_zookeeper():
                return False
                
            if not self.start_kafka():
                return False
            
            # Wait a bit more for Kafka to fully initialize before creating topics
            time.sleep(10)
                
            if not self.ensure_topics_exist():
                logger.warning("Failed to create some Kafka topics")
                
            self.is_running = True
            return True
        except Exception as e:
            logger.error(f"Error starting Kafka services: {e}")
            return False


def start_kafka_services():
    """Start Kafka and ZooKeeper if they're not already running"""
    try:
        # Check if we should auto-start Kafka
        from django.conf import settings
        auto_start = getattr(settings, 'AUTO_START_KAFKA', True)
        
        if not auto_start:
            logger.info("AUTO_START_KAFKA is disabled. Skipping Kafka autostart.")
            return False
            
        logger.info("Auto-starting Kafka services...")
        kafka_manager = KafkaManager.get_instance()
        success = kafka_manager.start_all()
        
        if success:
            logger.info("Kafka services started successfully")
        else:
            logger.warning("Failed to start Kafka services")
            
        return success
    except Exception as e:
        logger.error(f"Error in Kafka auto-start: {e}")
        return False