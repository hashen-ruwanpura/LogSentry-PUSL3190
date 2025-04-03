from django.core.management.base import BaseCommand
from log_ingestion.collectors import log_manager

class Command(BaseCommand):
    help = 'Start collecting logs from configured sources'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--daemon', 
            action='store_true', 
            help='Run as a daemon process'
        )
    
    def handle(self, *args, **options):
        self.stdout.write('Starting log collection...')
        
        success = log_manager.start_monitoring()
        
        if success:
            self.stdout.write(self.style.SUCCESS('Log collection started successfully'))
            
            # If running as daemon, keep process alive
            if options['daemon']:
                self.stdout.write('Running in daemon mode. Press Ctrl+C to stop.')
                try:
                    # Keep the process running
                    import time
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    self.stdout.write('Stopping log collection...')
                    log_manager.stop_monitoring()
                    self.stdout.write(self.style.SUCCESS('Log collection stopped'))
        else:
            self.stdout.write(self.style.ERROR('Failed to start log collection'))