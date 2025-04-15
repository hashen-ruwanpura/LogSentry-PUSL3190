from datetime import datetime, timedelta
from django.utils import timezone
from log_ingestion.models import ParsedLog
from analytics.models import LogReport
import logging
import ipaddress

logger = logging.getLogger(__name__)

def convert_log_to_report(parsed_log):
    """
    Convert a single ParsedLog to a LogReport entry
    Used for real-time report generation
    """
    try:
        # Check if this log has already been processed
        existing = LogReport.objects.filter(
            timestamp=parsed_log.timestamp,
            source_ip=parsed_log.source_ip,
            raw_log_id=parsed_log.id
        ).exists()
        
        if not existing:
            # Determine severity based on various factors
            severity = 'low'
            
            # Status codes for Apache logs
            if hasattr(parsed_log, 'status_code') and parsed_log.status_code:
                if parsed_log.status_code >= 500:
                    severity = 'high'
                elif parsed_log.status_code >= 400:
                    severity = 'medium'
            
            # Log level for other logs
            if hasattr(parsed_log, 'log_level') and parsed_log.log_level:
                if parsed_log.log_level in ['critical', 'error']:
                    severity = 'high'
                elif parsed_log.log_level in ['warning', 'warn']:
                    severity = 'medium'
            
            # Determine log type
            if hasattr(parsed_log, 'request_method') and parsed_log.request_method:
                log_type = 'apache'
            elif hasattr(parsed_log, 'query') and parsed_log.query:
                log_type = 'mysql'
            else:
                log_type = parsed_log.source_type if hasattr(parsed_log, 'source_type') else 'unknown'
            
            # Determine threat type
            threat_type = "General Log"
            if parsed_log.status == 'suspicious' or parsed_log.status == 'attack':
                threat_type = "Intrusion Attempt"
            elif hasattr(parsed_log, 'status_code') and parsed_log.status_code and parsed_log.status_code >= 400:
                threat_type = "Web Error"
            elif hasattr(parsed_log, 'execution_time') and parsed_log.execution_time and parsed_log.execution_time > 5:
                threat_type = "Performance Issue"
            
            # Create the report
            report = LogReport(
                timestamp=parsed_log.timestamp,
                log_type=log_type,
                source_ip=parsed_log.source_ip,
                country=detect_country(parsed_log.source_ip) if parsed_log.source_ip else None,
                threat_type=threat_type,
                severity=severity,
                status='Open',
                raw_log_id=parsed_log.id,
                description=str(parsed_log.normalized_data) if hasattr(parsed_log, 'normalized_data') else ''
            )
            
            # Apache specific fields
            if hasattr(parsed_log, 'request_method') and parsed_log.request_method:
                report.request_method = parsed_log.request_method
                report.request_path = parsed_log.request_path
                report.status_code = parsed_log.status_code
                report.response_size = parsed_log.response_size
                report.user_agent = parsed_log.user_agent
            
            # MySQL specific fields
            if hasattr(parsed_log, 'query') and parsed_log.query:
                report.database = parsed_log.database if hasattr(parsed_log, 'database') else None
                report.query_type = parsed_log.query_type if hasattr(parsed_log, 'query_type') else None
            
            report.save()
            logger.info(f"Created new report from log {parsed_log.id}")
            return report
        
    except Exception as e:
        logger.error(f"Error creating report from log {parsed_log.id}: {e}")
        return None

def detect_country(ip_address):
    """Simple placeholder for country detection - in production use a GeoIP library"""
    # This is a placeholder. In a real application, you would use a GeoIP database
    try:
        # Check if it's a private IP
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private:
            return "Local Network"
        
        # For demo purposes only - not accurate
        if ip_address.startswith('192.'):
            return "Local Network"
        elif ip_address.startswith('10.'):
            return "Local Network"
        elif ip_address.startswith('172.'):
            return "Local Network"
        else:
            # In production, use a proper GeoIP lookup
            return "Unknown"
    except:
        return "Unknown"

def convert_logs_to_reports():
    """
    Batch conversion of ParsedLog entries to LogReport entries
    For initial data population and scheduled tasks
    """
    try:
        # Get recent logs that haven't been processed yet
        recent_time = timezone.now() - timedelta(hours=24)
        recent_logs = ParsedLog.objects.filter(
            timestamp__gte=recent_time,
            log_level__isnull=False  # Only process logs with a log level
        )
        
        count = 0
        for log in recent_logs:
            report = convert_log_to_report(log)
            if report:
                count += 1
        
        logger.info(f"Batch converted {count} logs to reports")
        return count
    
    except Exception as e:
        logger.error(f"Error in batch log conversion: {e}")
        return 0