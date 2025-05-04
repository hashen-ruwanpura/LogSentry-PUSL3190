from django.core.management.base import BaseCommand
from log_ingestion.kafka_manager import KafkaManager

class Command(BaseCommand):
    help = 'Manage Kafka and ZooKeeper services'
    
    def add_arguments(self, parser):
        parser.add_argument(
            'action',
            choices=['start', 'status', 'create-topics'],
            help='The action to perform'
        )
    
    def handle(self, *args, **options):
        kafka_manager = KafkaManager.get_instance()
        action = options['action']
        
        if action == 'start':
            self.stdout.write('Starting Kafka services...')
            if kafka_manager.start_all():
                self.stdout.write(self.style.SUCCESS('Kafka services started successfully'))
            else:
                self.stdout.write(self.style.ERROR('Failed to start Kafka services'))
                
        elif action == 'status':
            zk_status = "Running" if kafka_manager.is_zookeeper_running() else "Not running"
            kafka_status = "Running" if kafka_manager.is_kafka_running() else "Not running"
            
            self.stdout.write(f"ZooKeeper: {zk_status}")
            self.stdout.write(f"Kafka: {kafka_status}")
            
        elif action == 'create-topics':
            self.stdout.write('Creating Kafka topics...')
            if kafka_manager.ensure_topics_exist():
                self.stdout.write(self.style.SUCCESS('Kafka topics created successfully'))
            else:
                self.stdout.write(self.style.ERROR('Failed to create Kafka topics'))