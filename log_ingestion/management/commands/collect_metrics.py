from django.core.management.base import BaseCommand
from authentication.views_predictive import store_system_metrics

class Command(BaseCommand):
    help = 'Collect and store system metrics for trend analysis'

    def handle(self, *args, **options):
        self.stdout.write('Collecting system metrics...')
        success = store_system_metrics()
        
        if success:
            self.stdout.write(self.style.SUCCESS('Successfully collected system metrics'))
        else:
            self.stdout.write(self.style.ERROR('Failed to collect system metrics'))