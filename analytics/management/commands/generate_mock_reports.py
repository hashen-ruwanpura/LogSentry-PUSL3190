from django.core.management.base import BaseCommand
from analytics.utils import convert_logs_to_reports

class Command(BaseCommand):
    help = 'Convert parsed logs to report entries'

    def handle(self, *args, **options):
        count = convert_logs_to_reports()
        self.stdout.write(
            self.style.SUCCESS(f'Successfully converted {count} logs to reports')
        )