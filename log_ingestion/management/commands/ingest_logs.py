from django.core.management.base import BaseCommand
from log_ingestion.collectors import EnhancedLogCollectionManager
import time
import logging
import os
import json

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Start real-time log ingestion and analysis'

    def add_arguments(self, parser):
        parser.add_argument('--config', type=str, help='Path to log collection config file')
        parser.add_argument('--use-filebeat', action='store_true', help='Use Filebeat for log collection')

    def handle(self, *args, **options):
        config_path = options.get('config')
        use_filebeat = options.get('use_filebeat', False)
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
        else:
            # Default configuration
            config = {
                'use_filebeat': use_filebeat,
                'filebeat_config': os.path.join(os.getcwd(), 'config', 'filebeat.yml'),
                'log_files': [
                    {
                        'path': os.path.join(os.getcwd(), 'test_logs', 'apache_access.log'),
                        'type': 'apache'
                    },
                    {
                        'path': os.path.join(os.getcwd(), 'test_logs', 'mysql_error.log'),
                        'type': 'mysql'
                    }
                ]
            }
        
        # Add command line option to config if specified
        if use_filebeat:
            config['use_filebeat'] = True
        
        manager = EnhancedLogCollectionManager(config)
        
        try:
            self.stdout.write(self.style.SUCCESS('Starting real-time log ingestion...'))
            observers, threads = manager.start_monitoring()
            
            # Keep the command running
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('Stopping log ingestion...'))
            manager.stop_monitoring()
            self.stdout.write(self.style.SUCCESS('Log ingestion stopped'))