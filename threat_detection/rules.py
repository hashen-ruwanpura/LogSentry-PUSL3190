import re
from datetime import timedelta
from django.utils import timezone
from log_ingestion.models import ParsedLog, Threat
import logging
from django.db.models import Count
from django.core.cache import cache

logger = logging.getLogger(__name__)

class Rule:
    def __init__(self, name, description, severity):
        self.name = name
        self.description = description
        self.severity = severity
    
    def evaluate(self, log_entry):
        """Evaluate if the log entry matches the rule's criteria"""
        raise NotImplementedError("Subclasses must implement this method")

class SQLInjectionRule(Rule):
    def __init__(self):
        super().__init__(
            "SQL Injection Attempt", 
            "Detected potential SQL injection pattern in request", 
            "high"
        )
        self.patterns = [
            r"(\b|'|\")(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*(FROM|INTO|WHERE|TABLE)",
            r"(\b|'|\")(--).*",
            r"(\b|'|\")(/\*.*\*/)",
        ]
    
    def evaluate(self, log_entry):
        if not log_entry.path:
            return False
            
        for pattern in self.patterns:
            if re.search(pattern, log_entry.path, re.IGNORECASE):
                return True
        return False

class BruteForceRule(Rule):
    def __init__(self):
        super().__init__(
            "Brute Force Attempt", 
            "Multiple failed login attempts detected from same IP", 
            "high"
        )
        self.threshold = 5  # Number of failed attempts
        self.timeframe = 5  # Minutes
    
    def evaluate(self, log_entry):
        # Only check login URLs
        if not log_entry.path or 'login' not in log_entry.path.lower():
            return False
            
        # Only consider failed login attempts (status codes 401, 403)
        if log_entry.status_code not in [401, 403]:
            return False
            
        # Use cache for faster lookups of recent failed attempts
        cache_key = f"bruteforce_{log_entry.source_ip}"
        failed_attempts = cache.get(cache_key, 0)
        
        # Increment the counter
        failed_attempts += 1
        cache.set(cache_key, failed_attempts, 60*self.timeframe)
        
        # Check if threshold is exceeded
        if failed_attempts >= self.threshold:
            return True
            
        # As a backup, also check the database
        time_threshold = timezone.now() - timedelta(minutes=self.timeframe)
        count = ParsedLog.objects.filter(
            source_ip=log_entry.source_ip,
            timestamp__gte=time_threshold,
            path__icontains='login',
            status_code__in=[401, 403]
        ).count()
        
        return count >= self.threshold

class RateLimitRule(Rule):
    def __init__(self):
        super().__init__(
            "Rate Limit Exceeded", 
            "Too many requests from the same IP in a short time period", 
            "medium"
        )
        self.threshold = 100  # Number of requests
        self.timeframe = 1    # Minutes
    
    def evaluate(self, log_entry):
        # Use cache for faster lookups
        cache_key = f"ratelimit_{log_entry.source_ip}"
        request_count = cache.get(cache_key, 0)
        
        # Increment the counter
        request_count += 1
        cache.set(cache_key, request_count, 60*self.timeframe)
        
        # Check if threshold is exceeded
        if request_count >= self.threshold:
            return True
            
        # As a backup, also check the database
        time_threshold = timezone.now() - timedelta(minutes=self.timeframe)
        count = ParsedLog.objects.filter(
            source_ip=log_entry.source_ip,
            timestamp__gte=time_threshold
        ).count()
        
        return count >= self.threshold

class RuleEngine:
    def __init__(self):
        self.rules = [
            SQLInjectionRule(),
            BruteForceRule(),
            RateLimitRule(),
        ]
    
    def analyze_log(self, log_entry):
        """
        Analyze a single log entry against all rules.
        Returns a list of detected threats.
        """
        detected_threats = []
        
        for rule in self.rules:
            try:
                if rule.evaluate(log_entry):
                    # Create a threat record
                    threat = Threat.objects.create(
                        rule_name=rule.name,
                        description=rule.description,
                        severity=rule.severity,
                        source_ip=log_entry.source_ip,
                        log_entry=log_entry
                    )
                    detected_threats.append(threat)
                    logger.warning(
                        f"Threat detected: {rule.name} from IP {log_entry.source_ip}"
                    )
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.name}: {e}")
                
        return detected_threats
    
    def analyze_logs_batch(self, logs):
        """
        Analyze a batch of logs against all rules.
        This is used for historical analysis.
        """
        all_threats = []
        for log_entry in logs:
            threats = self.analyze_log(log_entry)
            all_threats.extend(threats)
        return all_threats