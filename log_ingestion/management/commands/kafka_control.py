import os
import time
import subprocess
import socket
import logging
from django.core.management.base import BaseCommand
from django.conf import settings

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Start, stop, or check status of Kafka and ZooKeeper'
    
    def add_arguments(self, parser):
        parser.add_argument(
            'action',
            choices=['start', 'stop', 'status', 'restart'],
            help='Action to perform on Kafka services'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force stop services using process kill'
        )
    
    def handle(self, *args, **options):
        action = options['action']
        force = options.get('force', False)
        
        # Get Kafka home directory from settings
        kafka_home = getattr(settings, 'KAFKA_HOME', r"C:\Kafka_2.13-3.8.1")
        
        if not os.path.exists(kafka_home):
            self.stderr.write(self.style.ERROR(f"Kafka directory not found at {kafka_home}"))
            return
        
        if action == 'start':
            self._start_services(kafka_home)
        elif action == 'stop':
            self._stop_services(kafka_home, force)
        elif action == 'restart':
            self._stop_services(kafka_home, force)
            time.sleep(5)
            self._start_services(kafka_home)
        elif action == 'status':
            self._check_status()
    
    def _is_port_in_use(self, port):
        """Check if a port is in use"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0
    
    def _ensure_log_dirs(self, kafka_home):
        """Ensure Kafka log directories exist"""
        kafka_logs = os.path.join(kafka_home, "logs", "kafka-logs")
        zk_logs = os.path.join(kafka_home, "logs", "zookeeper")
        
        os.makedirs(kafka_logs, exist_ok=True)
        os.makedirs(zk_logs, exist_ok=True)
        
        self.stdout.write(f"Created log directories in {kafka_home}")
    
    def _start_services(self, kafka_home):
        """Start ZooKeeper and Kafka"""
        # First check if they're already running
        zk_running = self._is_port_in_use(2181)
        kafka_running = self._is_port_in_use(9092)
        
        if zk_running and kafka_running:
            self.stdout.write(self.style.SUCCESS("Both ZooKeeper and Kafka are already running"))
            return
        
        # Ensure log directories exist
        self._ensure_log_dirs(kafka_home)
        
        # Start ZooKeeper if not running
        if not zk_running:
            self.stdout.write("Starting ZooKeeper...")
            zk_script = os.path.join(kafka_home, "bin", "windows", "zookeeper-server-start.bat")
            zk_config = os.path.join(kafka_home, "config", "zookeeper.properties")
            
            try:
                # Fix: Use start command to open in new console window
                subprocess.Popen(
                    f'start cmd /k "{zk_script} {zk_config}"',
                    shell=True,
                    cwd=kafka_home
                )
                
                # Wait for ZooKeeper to start
                attempts = 0
                while attempts < 10:
                    if self._is_port_in_use(2181):
                        self.stdout.write(self.style.SUCCESS("ZooKeeper started successfully"))
                        break
                    time.sleep(2)
                    attempts += 1
                
                if attempts >= 10:
                    self.stderr.write(self.style.ERROR("Failed to start ZooKeeper after waiting"))
                    return
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"Error starting ZooKeeper: {e}"))
                return
        else:
            self.stdout.write("ZooKeeper is already running")
        
        # Start Kafka if not running
        if not kafka_running:
            self.stdout.write("Starting Kafka...")
            # Wait a bit longer for ZooKeeper to initialize fully
            time.sleep(5)
            
            kafka_script = os.path.join(kafka_home, "bin", "windows", "kafka-server-start.bat")
            kafka_config = os.path.join(kafka_home, "config", "server.properties")
            
            try:
                # Fix: Use start command to open in new console window
                subprocess.Popen(
                    f'start cmd /k "{kafka_script} {kafka_config}"',
                    shell=True,
                    cwd=kafka_home
                )
                
                # Wait for Kafka to start - increased timeout
                attempts = 0
                while attempts < 15:
                    if self._is_port_in_use(9092):
                        self.stdout.write(self.style.SUCCESS("Kafka started successfully"))
                        break
                    time.sleep(3)  # Increased time between checks
                    attempts += 1
                
                if attempts >= 15:
                    self.stderr.write(self.style.ERROR("Failed to start Kafka after waiting"))
                    return
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"Error starting Kafka: {e}"))
                return
        else:
            self.stdout.write("Kafka is already running")
        
        # Create topics if needed
        self._create_topics(kafka_home)
    
    def _stop_services(self, kafka_home, force=False):
        """Stop Kafka and ZooKeeper"""
        if force:
            self.stdout.write("Force stopping Kafka and ZooKeeper...")
            # Just kill Java processes - USE WITH CAUTION
            try:
                subprocess.run("taskkill /F /IM java.exe /FI \"WINDOWTITLE eq Kafka*\"", shell=True)
                subprocess.run("taskkill /F /IM java.exe /FI \"WINDOWTITLE eq Zookeeper*\"", shell=True)
                self.stdout.write(self.style.SUCCESS("Force stopped Kafka processes"))
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"Error force stopping services: {e}"))
        else:
            # Normal stop using scripts
            self.stdout.write("Stopping Kafka...")
            kafka_stop_script = os.path.join(kafka_home, "bin", "windows", "kafka-server-stop.bat")
            
            try:
                subprocess.run(kafka_stop_script, shell=True, check=True)
                self.stdout.write(self.style.SUCCESS("Kafka stop command executed"))
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"Error stopping Kafka: {e}"))
                
            # Stop ZooKeeper after Kafka
            time.sleep(5)
            self.stdout.write("Stopping ZooKeeper...")
            zk_stop_script = os.path.join(kafka_home, "bin", "windows", "zookeeper-server-stop.bat")
            
            try:
                subprocess.run(zk_stop_script, shell=True, check=True)
                self.stdout.write(self.style.SUCCESS("ZooKeeper stop command executed"))
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"Error stopping ZooKeeper: {e}"))
    
    def _check_status(self):
        """Check if Kafka and ZooKeeper are running"""
        zk_running = self._is_port_in_use(2181)
        kafka_running = self._is_port_in_use(9092)
        
        if zk_running:
            self.stdout.write("ZooKeeper: " + self.style.SUCCESS("RUNNING"))
        else:
            self.stdout.write("ZooKeeper: " + self.style.ERROR("NOT RUNNING"))
        
        if kafka_running:
            self.stdout.write("Kafka: " + self.style.SUCCESS("RUNNING"))
        else:
            self.stdout.write("Kafka: " + self.style.ERROR("NOT RUNNING"))
    
    def _create_topics(self, kafka_home):
        """Create required Kafka topics if they don't exist"""
        if not self._is_port_in_use(9092):
            self.stderr.write(self.style.ERROR("Kafka is not running, cannot create topics"))
            return
        
        topics = getattr(settings, 'KAFKA_TOPICS', ['raw_logs', 'apache_logs', 'mysql_logs'])
        
        for topic in topics:
            self.stdout.write(f"Ensuring topic exists: {topic}")
            topic_script = os.path.join(kafka_home, "bin", "windows", "kafka-topics.bat")
            
            try:
                subprocess.run([
                    topic_script,
                    "--create",
                    "--topic", topic,
                    "--bootstrap-server", "localhost:9092",
                    "--partitions", "3",
                    "--replication-factor", "1",
                    "--if-not-exists"
                ], check=True, stderr=subprocess.PIPE)
                
                self.stdout.write(self.style.SUCCESS(f"Topic {topic} created/verified"))
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.decode() if e.stderr else str(e)
                # If error contains "already exists" that's fine
                if "already exists" in error_msg:
                    self.stdout.write(f"Topic {topic} already exists")
                else:
                    self.stderr.write(self.style.ERROR(f"Error creating topic {topic}: {error_msg}"))
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"Error creating topic {topic}: {e}"))