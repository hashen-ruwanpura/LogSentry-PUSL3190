from django.core.management.base import BaseCommand
from django.utils import timezone
from log_ingestion.models import LogSource, RawLog, ParsedLog
import random
from datetime import timedelta

class Command(BaseCommand):
    help = 'Seed the database with sample Apache and MySQL logs'

    def handle(self, *args, **options):
        # Create source records if they don't exist
        apache_source, _ = LogSource.objects.get_or_create(
            name="Apache Web Server",
            source_type="apache",
            defaults={
                'file_path': '/var/log/apache2/access.log',
                'enabled': 1,
                'created_at': timezone.now(),
                'kafka_topic': 'apache_logs',
                'use_filebeat': 0
            }
        )
        
        mysql_source, _ = LogSource.objects.get_or_create(
            name="MySQL Database Server",
            source_type="mysql",
            defaults={
                'file_path': '/var/log/mysql/mysql.log',
                'enabled': 1,
                'created_at': timezone.now(),
                'kafka_topic': 'mysql_logs',
                'use_filebeat': 0
            }
        )
        
        self.stdout.write(self.style.SUCCESS('Created log sources'))
        
        # Create Apache logs
        http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]
        status_codes = [200, 201, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503]
        paths = ["/", "/index.html", "/login", "/profile", "/api/v1/users", "/static/css/main.css", "/static/js/app.js", "/favicon.ico", "/api/data"]
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        ]
        
        # Create Apache logs
        count = 0
        for i in range(20):  # Create 20 sample logs
            now = timezone.now() - timedelta(minutes=random.randint(1, 60*24))  # Random time in the last 24 hours
            method = random.choice(http_methods)
            status_code = random.choice(status_codes)
            path = random.choice(paths)
            user_agent = random.choice(user_agents)
            source_ip = f"192.168.1.{random.randint(1, 255)}"
            response_size = random.randint(100, 10000)
            
            # First create the RawLog
            content = f'{source_ip} - - [{now.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status_code} {response_size} "-" "{user_agent}"'
            
            # Explicitly ensure timestamp isn't null
            raw_log = RawLog(
                content=content,
                source=apache_source,
                timestamp=now,  # Set timestamp explicitly
                is_parsed=1,
                processing_status="processed"
            )
            raw_log.save()
            
            # Create ParsedLog referencing the RawLog
            parsed_log = ParsedLog(
                raw_log=raw_log,
                timestamp=now,  # Match timestamp with RawLog
                source_ip=source_ip,
                log_level="INFO",
                request_method=method,
                request_path=path,
                status_code=status_code,
                response_size=response_size,
                user_agent=user_agent,
                status="success",
                source_type="apache",
                normalized_data={},
                analyzed=0
            )
            parsed_log.save()
            count += 1
        
        self.stdout.write(self.style.SUCCESS(f'Created {count} Apache logs'))
        
        # Create MySQL logs
        count = 0
        query_types = ["SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "SHOW"]
        tables = ["users", "products", "orders", "inventory", "logs", "sessions"]
        users = ["admin", "app_user", "system", "webapp", "root"]
        
        for i in range(15):  # Create 15 sample logs
            now = timezone.now() - timedelta(minutes=random.randint(1, 60*24))  # Random time in the last 24 hours
            query_type = random.choice(query_types)
            table = random.choice(tables)
            user_id = random.choice(users)
            execution_time = random.uniform(0.01, 10.0)
            
            if query_type == "SELECT":
                query = f"SELECT * FROM {table} WHERE id > {random.randint(1, 1000)} LIMIT {random.randint(10, 100)}"
            elif query_type == "INSERT":
                query = f"INSERT INTO {table} (name, value) VALUES ('record-{random.randint(1, 100)}', {random.randint(1, 1000)})"
            elif query_type == "UPDATE":
                query = f"UPDATE {table} SET updated_at = NOW() WHERE id = {random.randint(1, 100)}"
            elif query_type == "DELETE":
                query = f"DELETE FROM {table} WHERE id = {random.randint(1, 100)}"
            else:
                query = f"{query_type} TABLE {table}"
            
            # Create RawLog for MySQL
            content = f"[{now.strftime('%Y-%m-%d %H:%M:%S')}] {user_id}[{random.randint(1000, 9999)}]: {query}; Execution time: {execution_time:.2f} sec"
            
            # Explicitly ensure timestamp isn't null
            raw_log = RawLog(
                content=content,
                source=mysql_source,
                timestamp=now,  # Set timestamp explicitly
                is_parsed=1,
                processing_status="processed"
            )
            raw_log.save()
            
            # Create ParsedLog for MySQL
            parsed_log = ParsedLog(
                raw_log=raw_log,
                timestamp=now,
                query=query,
                execution_time=execution_time,
                user_id=user_id,
                status="success",
                source_type="mysql",
                normalized_data={},
                analyzed=0
            )
            parsed_log.save()
            count += 1
            
        self.stdout.write(self.style.SUCCESS(f'Created {count} MySQL logs'))