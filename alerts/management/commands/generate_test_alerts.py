from django.core.management.base import BaseCommand
from django.utils import timezone
from alerts.models import Alert, AlertNote
from django.contrib.auth.models import User
import random
from datetime import timedelta
import ipaddress

class Command(BaseCommand):
    help = 'Generates test alerts for development and testing'

    def add_arguments(self, parser):
        parser.add_argument('--count', type=int, default=20, help='Number of alerts to generate')
        # Add the severity parameter
        parser.add_argument('--severity', type=str, choices=['low', 'medium', 'high', 'critical'], 
                           help='Generate alerts with a specific severity')

    def handle(self, *args, **options):
        count = options['count']
        specific_severity = options.get('severity')
        
        # Get or create an admin user for notes
        admin_user, _ = User.objects.get_or_create(
            username='admin',
            defaults={'is_staff': True, 'is_superuser': True, 'email': 'admin@example.com'}
        )
        
        # Set up sample data
        alert_sources = ['Apache', 'MySQL', 'Firewall', 'IDS', 'Authentication Service', 'Web Server']
        ip_ranges = ['192.168.1.0/24', '10.0.0.0/24', '172.16.0.0/16', '203.0.113.0/24']
        usernames = ['root', 'admin', 'user1', 'guest', 'system', 'www-data', 'mysql']
        systems = ['Web server', 'Database server', 'Authentication system', 'API gateway', 
                   'Load balancer', 'SSH server', 'File server']
        
        mitre_tactics = [
            'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
            'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
            'Collection', 'Command and Control', 'Exfiltration', 'Impact'
        ]
        
        descriptions = {
            'intrusion': [
                'Multiple failed SSH login attempts detected from IP {ip}',
                'Possible SQL injection attempt from IP {ip}',
                'XSS attack attempt detected from IP {ip}',
                'File inclusion attempt detected from IP {ip}',
                'Directory traversal attempt from IP {ip}'
            ],
            'malware': [
                'Suspicious file upload detected from IP {ip}',
                'Malware signature detected in uploaded file from {ip}',
                'Malicious script execution attempt from {ip}',
                'Virus detected in email attachment from {ip}',
                'Ransomware-like behavior detected on server'
            ],
            'authentication': [
                'Multiple failed login attempts for user {user} from IP {ip}',
                'Password guessing attack detected for user {user}',
                'Brute force attack detected on login page from IP {ip}',
                'Possible credential stuffing attack from IP {ip}',
                'Failed admin login attempts from unusual IP {ip}'
            ],
            'anomaly': [
                'Unusual database query pattern from user {user}',
                'Abnormal traffic spike from IP {ip}',
                'Unusual system resource usage detected',
                'Abnormal API usage pattern from IP {ip}',
                'Off-hours system access from user {user}'
            ],
            'policy': [
                'Unauthorized access attempt to restricted resource by {user}',
                'Data export policy violation by user {user}',
                'Sensitive data access from unauthorized IP {ip}',
                'Compliance violation detected in database query',
                'Restricted command execution attempt by user {user}'
            ]
        }
        
        recommendations = {
            'intrusion': 'Block the source IP and review firewall rules. Consider implementing rate limiting.',
            'malware': 'Isolate affected systems, scan for malware, and update antivirus definitions.',
            'authentication': 'Reset user credentials, implement multi-factor authentication, and review login policies.',
            'anomaly': 'Investigate the unusual activity, verify with the user if legitimate, and update baseline if needed.',
            'policy': 'Review user permissions, reinforce security policies, and implement additional controls.'
        }

        # Generate random alerts
        generated_count = 0
        self.stdout.write(f"Generating {count} test alerts...")
        
        for _ in range(count):
            # Pick random values
            alert_type = random.choice([k for k, v in Alert.TYPE_CHOICES])
            # Use specific severity if provided, otherwise random
            if specific_severity:
                severity = specific_severity
            else:
                severity = random.choice([k for k, v in Alert.SEVERITY_CHOICES])
            source = random.choice(alert_sources)
            status = random.choice(['new', 'investigating'] if severity in ['critical', 'high'] else 
                                  [k for k, v in Alert.STATUS_CHOICES])
            
            # Generate a random IP in one of our ranges
            network = ipaddress.ip_network(random.choice(ip_ranges))
            host_bits = random.randint(0, 2**(32 - network.prefixlen) - 1)
            ip_address = str(network.network_address + host_bits)
            
            # Pick a random user
            username = random.choice(usernames)
            
            # Pick random affected systems
            affected = ', '.join(random.sample(systems, k=random.randint(1, 3)))
            
            # Pick random MITRE tactics
            tactics = ', '.join(random.sample(mitre_tactics, k=random.randint(1, 3)))
            
            # Generate timestamp (within the last 7 days)
            time_offset = random.randint(0, 7 * 24 * 60 * 60)  # seconds in 7 days
            timestamp = timezone.now() - timedelta(seconds=time_offset)
            
            # Generate description
            description_template = random.choice(descriptions[alert_type])
            description = description_template.format(ip=ip_address, user=username)
            
            # Get recommendation
            recommendation = recommendations[alert_type]
            
            # Create the alert
            alert = Alert(
                timestamp=timestamp,
                type=alert_type,
                source=source,
                severity=severity,
                status=status,
                description=description,
                ip_address=ip_address,
                user=username,
                affected_systems=affected,
                mitre_tactics=tactics,
                recommendation=recommendation,
                detection_time=random.uniform(10, 500),  # Random detection time between 10-500ms
                raw_log_id=random.randint(10000, 99999),
                parsed_log_id=random.randint(10000, 99999),
            )
            
            # Add some analysis data for analyzed alerts
            if random.random() > 0.7:  # 30% of alerts are analyzed
                alert.is_analyzed = True
                alert.last_analyzed = timestamp + timedelta(seconds=random.randint(60, 3600))
                alert.analysis_data = {
                    'risk_score': random.randint(30, 95),
                    'false_positive_probability': random.uniform(0.1, 0.4),
                    'similar_incidents_last_30_days': random.randint(0, 15),
                    'analyzed_by': 'auto' if random.random() > 0.5 else 'admin'
                }
            
            alert.save()
            generated_count += 1
            
            # Add notes for some alerts
            if random.random() > 0.6:  # 40% of alerts have notes
                num_notes = random.randint(1, 3)
                for i in range(num_notes):
                    note_time = alert.timestamp + timedelta(seconds=random.randint(300, 7200))
                    
                    note_texts = [
                        f"Investigating this alert. IP appears on threat intelligence feed.",
                        f"This looks like part of a scanning pattern we've seen before.",
                        f"Checking if this is related to the maintenance window.",
                        f"Correlating with other logs to determine scope.",
                        f"Similar pattern observed last week from different IP range.",
                        f"Appears to be a false positive related to monitoring system.",
                        f"Confirmed malicious activity, blocking IP at firewall."
                    ]
                    
                    AlertNote.objects.create(
                        alert=alert,
                        content=random.choice(note_texts),
                        timestamp=note_time,
                        created_by=admin_user
                    )
        
        self.stdout.write(self.style.SUCCESS(f'Successfully generated {generated_count} test alerts'))