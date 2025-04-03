import re
import json
import ipaddress
from abc import ABC, abstractmethod
from django.utils import timezone
from django.conf import settings
from log_ingestion.models import ParsedLog
from .models import DetectionRule, Threat, BlacklistedIP

class BaseRule(ABC):
    """Base class for all detection rules"""
    
    def __init__(self, rule_config):
        self.rule_config = rule_config
        self.name = rule_config.name
        self.description = rule_config.description
        self.severity = rule_config.severity
        self.mitre_technique = rule_config.mitre_technique
    
    @abstractmethod
    def matches(self, parsed_log):
        """Check if the rule matches this log entry"""
        pass
    
    def is_false_positive(self, parsed_log):
        """Check if this is likely a false positive"""
        # Check against whitelisted IPs
        if parsed_log.source_ip:
            whitelist = getattr(settings, 'WHITELISTED_IPS', [])
            if parsed_log.source_ip in whitelist:
                return True
        return False
    
    def get_description(self, parsed_log):
        """Get a description of the threat"""
        return f"Detected {self.name} in log from {parsed_log.source_ip or 'unknown source'}"
    
    def create_threat(self, parsed_log):
        """Create a threat entry for this rule match"""
        # Don't create if it's a false positive
        if self.is_false_positive(parsed_log):
            return None
            
        # Create the threat
        threat = Threat.objects.create(
            rule=self.rule_config,
            parsed_log=parsed_log,
            severity=self.severity,
            description=self.get_description(parsed_log),
            source_ip=parsed_log.source_ip,
            user_id=parsed_log.user_id,
            mitre_technique=self.mitre_technique
        )
        
        # Update parsed log status
        parsed_log.status = 'suspicious' if self.severity in ['low', 'medium'] else 'attack'
        parsed_log.save(update_fields=['status'])
        
        # Take actions for this threat
        self.take_action(parsed_log, threat)
        
        return threat
    
    def take_action(self, parsed_log, threat):
        """Take actions based on the detection (e.g., blacklist IP)"""
        # For high severity threats, consider blacklisting the IP
        if self.severity in ['high', 'critical'] and parsed_log.source_ip:
            # Check if already blacklisted
            existing = BlacklistedIP.objects.filter(
                ip_address=parsed_log.source_ip, 
                active=True
            ).exists()
            
            if not existing:
                # Create blacklist entry with expiry of 24 hours
                BlacklistedIP.objects.create(
                    ip_address=parsed_log.source_ip,
                    reason=f"Automatic blacklist due to {self.name}",
                    threat=threat,
                    expires_at=timezone.now() + timezone.timedelta(hours=24)
                )

class SQLInjectionRule(BaseRule):
    """Rule to detect SQL injection attempts"""
    
    # SQL injection patterns
    PATTERNS = [
        r'(\b|\'|\")?(OR|AND)(\s+|\+)1(\s+|\+)?=(\s+|\+)?1(\b|\'|\")?',
        r'(\b|\'|\")?(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)(\s+|\+)',
        r'--(\s+|\+)?$',
        r';(\s+|\+)?(--|\#|\/\*)',
        r'\/\*.*\*\/',
    ]
    
    def matches(self, parsed_log):
        if not parsed_log.request_path and not parsed_log.query:
            return False
            
        content_to_check = ""
        if parsed_log.request_path:
            content_to_check += parsed_log.request_path
        if parsed_log.query:
            content_to_check += parsed_log.query
            
        # Check each pattern
        for pattern in self.PATTERNS:
            if re.search(pattern, content_to_check, re.IGNORECASE):
                return True
                
        return False

class XSSAttackRule(BaseRule):
    """Rule to detect Cross-Site Scripting (XSS) attempts"""
    
    # XSS patterns
    PATTERNS = [
        r'<script.*?>',
        r'javascript:',
        r'onerror\s*=',
        r'onload\s*=',
        r'eval\s*\(',
        r'document\.cookie',
        r'alert\s*\(',
    ]
    
    def matches(self, parsed_log):
        if not parsed_log.request_path and not parsed_log.normalized_data:
            return False
            
        content_to_check = ""
        if parsed_log.request_path:
            content_to_check += parsed_log.request_path
            
        # Also check query params and POST data if available
        normalized_data = parsed_log.normalized_data
        if 'query_string' in normalized_data:
            content_to_check += normalized_data['query_string']
            
        # Check each pattern
        for pattern in self.PATTERNS:
            if re.search(pattern, content_to_check, re.IGNORECASE):
                return True
                
        return False

class BruteForceRule(BaseRule):
    """Rule to detect brute force login attempts"""
    
    def matches(self, parsed_log):
        # This requires some state tracking and can't just check a single log
        # We'll implement a simplified version that checks for 401/403 errors
        
        if not parsed_log.status_code:
            return False
            
        # Match failed authentication attempts
        if parsed_log.status_code in [401, 403]:
            # Check if this IP has had multiple failures recently
            recent_failures = ParsedLog.objects.filter(
                source_ip=parsed_log.source_ip,
                status_code__in=[401, 403],
                timestamp__gte=timezone.now() - timezone.timedelta(minutes=10)
            ).count()
            
            # Threshold of 5 failures in 10 minutes
            return recent_failures >= 5
                
        return False

class MaliciousRequestRule(BaseRule):
    """Rule to detect malicious or suspicious requests"""
    
    # Suspicious patterns in URLs
    PATTERNS = [
        r'\/etc\/passwd',
        r'\.\.\/\.\.\/\.\.', # Path traversal
        r'cmd\.exe',
        r'\.php\.suspected',
        r'wp-config\.php',
        r'\/\.git\/',
        r'\/\.env',
    ]
    
    def matches(self, parsed_log):
        if not parsed_log.request_path:
            return False
            
        # Check each pattern against the request path
        for pattern in self.PATTERNS:
            if re.search(pattern, parsed_log.request_path):
                return True
                
        return False

class ErrorRateRule(BaseRule):
    """Rule to detect abnormal error rates"""
    
    def matches(self, parsed_log):
        # This is a rate-based rule that requires checking multiple logs
        if not parsed_log.status_code or parsed_log.status_code < 500:
            return False
            
        # Check if there are many 5xx errors in the last few minutes
        recent_errors = ParsedLog.objects.filter(
            status_code__gte=500,
            timestamp__gte=timezone.now() - timezone.timedelta(minutes=5)
        ).count()
        
        # Threshold of 10 server errors in 5 minutes
        return recent_errors >= 10

class SlowQueryRule(BaseRule):
    """Rule to detect abnormally slow database queries"""
    
    def matches(self, parsed_log):
        # Check execution time threshold for MySQL queries
        if 'mysql' not in parsed_log.normalized_data.get('log_type', ''):
            return False
            
        execution_time = parsed_log.execution_time
        if not execution_time:
            return False
            
        # Threshold: 10 seconds is very slow for a query
        return execution_time > 10.0

class RuleEngine:
    """Engine that applies all active rules to logs"""
    
    def __init__(self):
        self.rules = {}
        self.load_rules()
    
    def load_rules(self):
        """Load all active rules from the database"""
        self.rules = {}
        
        # Get all active rules from the database
        db_rules = DetectionRule.objects.filter(active=True)
        
        for rule_config in db_rules:
            try:
                # Create the appropriate rule instance based on type
                if rule_config.rule_type == 'sql_injection':
                    self.rules[rule_config.id] = SQLInjectionRule(rule_config)
                elif rule_config.rule_type == 'xss':
                    self.rules[rule_config.id] = XSSAttackRule(rule_config)
                elif rule_config.rule_type == 'brute_force':
                    self.rules[rule_config.id] = BruteForceRule(rule_config)
                elif rule_config.rule_type == 'malicious_request':
                    self.rules[rule_config.id] = MaliciousRequestRule(rule_config)
                elif rule_config.rule_type == 'error_rate':
                    self.rules[rule_config.id] = ErrorRateRule(rule_config)
                elif rule_config.rule_type == 'slow_query':
                    self.rules[rule_config.id] = SlowQueryRule(rule_config)
            except Exception as e:
                print(f"Error loading rule {rule_config.name}: {str(e)}")
    
    def analyze_log(self, parsed_log):
        """Analyze a parsed log against all active rules"""
        matched_rules = []
        threats = []
        
        for rule_id, rule in self.rules.items():
            try:
                if rule.matches(parsed_log):
                    matched_rules.append(rule)
                    threat = rule.create_threat(parsed_log)
                    if threat:
                        threats.append(threat)
            except Exception as e:
                print(f"Error applying rule {rule.name}: {str(e)}")
        
        return threats, matched_rules