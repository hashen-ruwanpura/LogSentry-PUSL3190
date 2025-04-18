from django.utils import timezone
from log_ingestion.models import RawLog, ParsedLog, LogSource
from threat_detection.models import Threat, DetectionRule
import random
from datetime import timedelta
import ipaddress
from django.db import transaction

def generate_test_data(apache_count=100, mysql_count=50, threat_count=20):
    """Generate test data for the dashboard"""
    print(f"Generating {apache_count} Apache logs, {mysql_count} MySQL logs and {threat_count} threats...")
    
    # Use transaction.atomic to speed up bulk inserts and reduce signal triggering
    with transaction.atomic():
        # Create or get LogSource objects
        apache_source, _ = LogSource.objects.get_or_create(name='Apache')
        mysql_source, _ = LogSource.objects.get_or_create(name='MySQL')
        
        # Create rule if it doesn't exist
        rule, _ = DetectionRule.objects.get_or_create(
            name="SQL Injection Attempt",
            defaults={
                'description': 'Detected potential SQL injection pattern in request',
                'rule_type': 'SQLInjectionRule',
                'severity': 'high',
                'enabled': True,
                'mitre_technique_id': 'T1190',
                'mitre_tactic': 'Initial Access'
            }
        )
        
        # Sample user agents
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0)'
        ]
        
        # Sample Apache paths
        apache_paths = [
            '/login', '/admin', '/dashboard', '/api/users', '/static/main.css',
            '/images/logo.png', '/api/data', '/register', '/logout', '/profile'
        ]
        
        # Sample MySQL queries
        mysql_queries = [
            'SELECT * FROM users WHERE username=?',
            'INSERT INTO logs (timestamp, level, message) VALUES (?, ?, ?)',
            'UPDATE users SET last_login=? WHERE id=?',
            'DELETE FROM sessions WHERE expires_at < ?',
            'SELECT COUNT(*) FROM events WHERE date > ?'
        ]
        
        # Create Apache logs - simpler approach creating them one by one
        print("Creating Apache logs...")
        for i in range(apache_count):
            # Generate timestamp between now and 30 days ago
            timestamp = timezone.now() - timedelta(days=random.randint(0, 30), 
                                                 hours=random.randint(0, 23),
                                                 minutes=random.randint(0, 59))
            
            # Generate source IP
            ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
            # Select random elements
            path = random.choice(apache_paths)
            method = random.choice(['GET', 'POST', 'PUT', 'DELETE'])
            status_code = random.choice([200, 200, 200, 200, 404, 500, 403, 401])
            user_agent = random.choice(user_agents)
            
            # Determine log status
            if status_code == 401 or status_code == 403:
                status = 'authentication_failure'
            elif status_code >= 500:
                status = 'error'
            else:
                status = 'normal'
            
            # Create raw log
            content = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S")}] "{method} {path} HTTP/1.1" {status_code} {random.randint(200, 5000)}'
            raw_log = RawLog.objects.create(
                source=apache_source,
                content=content,
                timestamp=timestamp
            )
            
            # Create parsed log - no need to parse from content, we have the values already
            ParsedLog.objects.create(
                raw_log=raw_log,
                timestamp=timestamp,
                source_ip=ip,
                request_path=path,
                request_method=method,
                status_code=status_code,
                user_id='admin' if random.random() > 0.8 else None,
                response_size=random.randint(500, 10000),
                user_agent=user_agent,
                execution_time=random.uniform(0.05, 2.0),
                status=status,
                normalized_data={
                    'ip': ip,
                    'path': path,
                    'method': method,
                    'status_code': status_code,
                    'user_agent': user_agent
                },
                source_type='apache'
            )
            
            # Print progress periodically
            if i % 20 == 0:
                print(f"Created {i}/{apache_count} Apache logs")
        
        # Create MySQL logs
        print("Creating MySQL logs...")
        for i in range(mysql_count):
            # Generate timestamp between now and 30 days ago
            timestamp = timezone.now() - timedelta(days=random.randint(0, 30), 
                                                 hours=random.randint(0, 23),
                                                 minutes=random.randint(0, 59))
            
            # Generate source IP
            ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
            # Select random query
            query = random.choice(mysql_queries)
            db = random.choice(['users_db', 'products_db', 'logs_db'])
            
            # Create raw log
            content = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} {random.randint(10000, 99999)} Query\t{query}"
            raw_log = RawLog.objects.create(
                source=mysql_source,
                content=content,
                timestamp=timestamp
            )
            
            # Create parsed log
            ParsedLog.objects.create(
                raw_log=raw_log,
                timestamp=timestamp,
                source_ip=ip,
                query=query,
                execution_time=random.uniform(0.001, 1.5),
                status='normal',
                normalized_data={
                    'db': db,
                    'query_type': query.split()[0],
                    'table': query.split('FROM ')[1].split()[0] if ' FROM ' in query else '',
                    'execution_time': random.uniform(0.001, 1.5)
                },
                source_type='mysql'
            )
            
            # Print progress periodically
            if i % 10 == 0:
                print(f"Created {i}/{mysql_count} MySQL logs")
        
        # Create threats
        print("Creating threats...")
        mitre_tactics = [
            'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
            'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement'
        ]
        
        # Get all parsed logs for threat generation
        logs = list(ParsedLog.objects.all().order_by('?')[:threat_count])
        
        for i, log in enumerate(logs):
            try:
                # Generate threat
                severity = random.choice(['low', 'medium', 'high', 'critical'])
                tactic = random.choice(mitre_tactics)
                
                Threat.objects.create(
                    rule=rule,
                    parsed_log=log,
                    description=f"Potential security threat detected from {log.source_ip}",
                    severity=severity,
                    status=random.choice(['new', 'investigating', 'resolved']),
                    source_ip=log.source_ip,
                    user_id=log.user_id,
                    affected_system=log.source_type.capitalize() + ' server',
                    mitre_technique='T1190',
                    mitre_tactic=tactic,
                    recommendation=f"Block the source IP {log.source_ip} and review firewall rules."
                )
                
                # Print progress
                if (i+1) % 5 == 0:
                    print(f"Created {i+1}/{len(logs)} threats")
                
            except Exception as e:
                print(f"Error creating threat: {e}")
    
    print("Test data generation complete!")

if __name__ == "__main__":
    # This allows running via `python manage.py shell < generate_test_logs.py`
    generate_test_data()