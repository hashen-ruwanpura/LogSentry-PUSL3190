from django.core.management.base import BaseCommand
from analytics.models import LogReport
from django.utils import timezone
import random
from datetime import timedelta
import ipaddress

class Command(BaseCommand):
    help = 'Generates mock LogReport data for testing'

    def add_arguments(self, parser):
        parser.add_argument('count', type=int, help='Number of log reports to generate')

    def handle(self, *args, **options):
        count = options['count']
        
        # Sample data
        log_types = ['apache', 'mysql']
        severities = ['high', 'medium', 'low']
        statuses = ['open', 'in_progress', 'resolved']
        
        apache_threat_types = [
            'SQL Injection Attempt', 
            'Cross-Site Scripting (XSS)', 
            'Path Traversal', 
            'Command Injection',
            'Suspicious User Agent', 
            'Brute Force Login Attempt',
            '404 Not Found',
            '403 Forbidden',
            '500 Internal Server Error'
        ]
        
        mysql_threat_types = [
            'Excessive Privileges', 
            'Table Drop Attempt', 
            'Suspicious Query',
            'High Resource Usage', 
            'Failed Login Attempt', 
            'Database Configuration Change'
        ]
        
        countries = [
            ('US', 'United States'),
            ('CN', 'China'),
            ('RU', 'Russia'),
            ('DE', 'Germany'),
            ('GB', 'United Kingdom'),
            ('FR', 'France'),
            ('BR', 'Brazil'),
            ('IN', 'India'),
            ('JP', 'Japan'),
            ('KR', 'South Korea')
        ]
        
        request_methods = ['GET', 'POST', 'PUT', 'DELETE']
        request_paths = [
            '/login.php', 
            '/admin/', 
            '/wp-login.php', 
            '/phpmyadmin/',
            '/api/users', 
            '/includes/config.php', 
            '/uploads/shell.php',
            '/search?q=1%27%20OR%201=1',
            '/product?id=1%20OR%201=1'
        ]
        
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'sqlmap/1.4.9 (http://sqlmap.org)',
            'Nmap Scripting Engine',
            'python-requests/2.25.1',
            'curl/7.68.0'
        ]
        
        databases = ['users', 'products', 'orders', 'logs', 'customers']
        query_types = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER']
        
        # Generate log reports
        reports = []
        now = timezone.now()
        
        for i in range(count):
            # Random timestamp within the last 30 days
            days_ago = random.randint(0, 30)
            hours_ago = random.randint(0, 23)
            minutes_ago = random.randint(0, 59)
            timestamp = now - timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
            
            # Random IP address
            ip_int = random.randint(167772160, 4294967295)  # Range from 10.0.0.0 to 255.255.255.255
            source_ip = str(ipaddress.IPv4Address(ip_int))
            
            # Random log type
            log_type = random.choice(log_types)
            
            # Set threat type based on log type
            if log_type == 'apache':
                threat_type = random.choice(apache_threat_types)
            else:
                threat_type = random.choice(mysql_threat_types)
            
            # Set severity with weighted distribution (fewer high severity)
            severity_weights = [0.2, 0.3, 0.5]  # 20% high, 30% medium, 50% low
            severity = random.choices(severities, weights=severity_weights)[0]
            
            # Set status with weighted distribution (more open than resolved)
            if severity == 'high':
                status_weights = [0.6, 0.3, 0.1]  # High severity more likely to be open
            else:
                status_weights = [0.4, 0.3, 0.3]
            
            status = random.choices(statuses, weights=status_weights)[0]
            
            # Set country
            country = random.choice(countries)
            country_code = country[0]
            country_name = country[1]
            
            # Generate raw log
            if log_type == 'apache':
                raw_log = f'{source_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] "{random.choice(request_methods)} {random.choice(request_paths)} HTTP/1.1" {random.randint(200, 500)} {random.randint(200, 5000)} "-" "{random.choice(user_agents)}"'
                
                # Apache specific fields
                request_method = random.choice(request_methods)
                request_path = random.choice(request_paths)
                status_code = random.randint(200, 500)
                response_size = random.randint(200, 5000)
                user_agent = random.choice(user_agents)
                
                # MySQL specific fields
                database = None
                query_type = None
            else:
                db = random.choice(databases)
                qtype = random.choice(query_types)
                raw_log = f'{timestamp.strftime("%Y-%m-%d %H:%M:%S")} {random.randint(1, 9999)} [Warning] {source_ip} {qtype} query on {db}: {qtype} FROM {db}.users WHERE username=\'admin\' AND password=\'\' OR \'1\'=\'1\''
                
                # Apache specific fields
                request_method = None
                request_path = None
                status_code = None
                response_size = None
                user_agent = None
                
                # MySQL specific fields
                database = db
                query_type = qtype
            
            # Create LogReport instance
            report = LogReport(
                timestamp=timestamp,
                log_type=log_type,
                source_ip=source_ip,
                country_code=country_code,
                country_name=country_name,
                threat_type=threat_type,
                severity=severity,
                status=status,
                raw_log=raw_log,
                request_method=request_method,
                request_path=request_path,
                status_code=status_code,
                response_size=response_size,
                user_agent=user_agent,
                database=database,
                query_type=query_type
            )
            
            reports.append(report)
        
        # Bulk create
        LogReport.objects.bulk_create(reports)
        
        self.stdout.write(self.style.SUCCESS(f'Successfully generated {count} mock log reports'))