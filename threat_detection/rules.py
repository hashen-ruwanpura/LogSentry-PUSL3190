import re
import logging
from datetime import timedelta
from django.db import models
from django.utils import timezone
from log_ingestion.models import ParsedLog, Threat
from .models import DetectionRule, Threat
from django.core.cache import cache

logger = logging.getLogger(__name__)

# Base Rule class
class Rule:
    def __init__(self, name, description, severity='medium'):
        self.name = name
        self.description = description
        self.severity = severity
        
    def evaluate(self, log_entry):
        """Evaluate if the rule matches the log entry"""
        raise NotImplementedError("Each rule must implement evaluate method")

# SQL Injection detection rule
class SQLInjectionRule(Rule):
    def __init__(self):
        super().__init__(
            "SQL Injection Attempt", 
            "Detected potential SQL injection pattern in request",
            "high"
        )
        
        # Common SQL injection patterns
        self.patterns = [
            r"(?i)('|\").*?(\s|;)+(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)",
            r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION).*?FROM",
            r"(?i)(--).*?$",
            r"(?i)(\/\*).*?(\*\/)",
            r"(?i);.*?$"
        ]
        
    def evaluate(self, log_entry):
        """Check for SQL injection patterns in request"""
        if not log_entry:
            return False
            
        # Check request path
        if log_entry.request_path:
            for pattern in self.patterns:
                if re.search(pattern, log_entry.request_path):
                    return True
                    
        # Check query if available
        if log_entry.query:
            for pattern in self.patterns:
                if re.search(pattern, log_entry.query):
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

# Enhanced Rule Engine with MITRE integration
class EnhancedRuleEngine:
    def __init__(self):
        self.rules = [
            SQLInjectionRule(),
            # Add more built-in rules
        ]
        self.db_rules = None
    
    def _get_db_rules(self):
        """Load detection rules from database"""
        if self.db_rules is None:
            self.db_rules = list(DetectionRule.objects.filter(enabled=True))
        return self.db_rules
    
    def _get_or_create_rule(self, rule):
        """Get or create a database rule entry for a rule object"""
        try:
            db_rule = DetectionRule.objects.get(name=rule.name)
        except DetectionRule.DoesNotExist:
            db_rule = DetectionRule.objects.create(
                name=rule.name,
                description=rule.description,
                rule_type=rule.__class__.__name__,
                severity=rule.severity,
                pattern=getattr(rule, 'patterns', [])[0] if hasattr(rule, 'patterns') else None
            )
        return db_rule
    
    def analyze_log(self, log_entry):
        """Analyze a log entry against all rules"""
        detected_threats = []
        
        for rule in self.rules:
            try:
                if rule.evaluate(log_entry):
                    # Create a threat record
                    threat = Threat.objects.create(
                        rule=self._get_or_create_rule(rule),
                        parsed_log=log_entry,
                        description=rule.description,
                        severity=rule.severity,
                        source_ip=log_entry.source_ip,
                        user_id=log_entry.user_id
                    )
                    detected_threats.append(threat)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.__class__.__name__}: {e}")
                
        # Check database rules
        for db_rule in self._get_db_rules():
            try:
                if db_rule.pattern and log_entry.normalized_data:
                    # Simple pattern matching against normalized data
                    log_str = str(log_entry.normalized_data)
                    if re.search(db_rule.pattern, log_str):
                        threat = Threat.objects.create(
                            rule=db_rule,
                            parsed_log=log_entry,
                            description=db_rule.description,
                            severity=db_rule.severity,
                            source_ip=log_entry.source_ip,
                            user_id=log_entry.user_id,
                            mitre_technique=db_rule.mitre_technique_id,
                            mitre_tactic=db_rule.mitre_tactic
                        )
                        detected_threats.append(threat)
            except Exception as e:
                logger.error(f"Error evaluating database rule {db_rule.name}: {e}")
                
        return detected_threats

# Add to threat_detection/models.py
class RecommendationTemplate(models.Model):
    """Templates for security recommendations"""
    threat_type = models.CharField(max_length=50)  # SQL injection, brute force, etc.
    severity = models.CharField(max_length=10, choices=DetectionRule.SEVERITY_CHOICES)
    template = models.TextField()  # Template with placeholders
    system_type = models.CharField(max_length=50, blank=True, null=True)  # web, db, auth, etc.
    
    def __str__(self):
        return f"{self.threat_type} - {self.severity} - {self.system_type or 'generic'}"

# Add to threat_detection/models.py - Threat model
def get_recommendation(self):
    """Generate a context-aware recommendation"""
    # Try to get a specific template
    template = RecommendationTemplate.objects.filter(
        threat_type=self.rule.rule_type,
        severity=self.severity,
        system_type=self.affected_system
    ).first()
    
    # Fall back to generic template
    if not template:
        template = RecommendationTemplate.objects.filter(
            threat_type=self.rule.rule_type,
            severity=self.severity,
            system_type__isnull=True
        ).first()
    
    if not template:
        return "No specific recommendation available."
    
    # Replace placeholders with context
    recommendation = template.template
    context = {
        'ip': self.source_ip or 'unknown',
        'user': self.user_id or 'unknown',
        'path': self.parsed_log.request_path if self.parsed_log else 'unknown',
        'pattern': self.rule.pattern or 'unknown',
        'timestamp': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'incident_count': self.incidents.count()
    }
    
    for key, value in context.items():
        recommendation = recommendation.replace(f"{{{key}}}", str(value))
    
    return recommendation