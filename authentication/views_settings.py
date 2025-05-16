import json
import os
import logging
import tempfile
import re
from datetime import datetime, timedelta
import threading
import time

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.conf import settings
from django.utils import timezone
from django.db import transaction
from django.core.files.storage import FileSystemStorage

from log_ingestion.models import LogSource, RawLog, ParsedLog, LogFilePosition
from threat_detection.models import Threat, DetectionRule
from alerts.models import NotificationPreference
from alerts.services import AlertService
from .views import validate_log_file
from log_ingestion.realtime_processor import RealtimeLogProcessor

# Configure logger
logger = logging.getLogger(__name__)


@login_required
def settings_view(request):
    """Main settings view handler"""
    # Get log source settings without default values
    apache_log_path = ""
    mysql_log_path = ""
    
    try:
        apache_source = LogSource.objects.get(name='Apache Web Server')
        if apache_source.file_path and apache_source.file_path != '.':
            apache_log_path = apache_source.file_path
    except LogSource.DoesNotExist:
        pass
    
    try:    
        mysql_source = LogSource.objects.get(name='MySQL Database Server')
        if mysql_source.file_path and mysql_source.file_path != '.':
            mysql_log_path = mysql_source.file_path
    except LogSource.DoesNotExist:
        pass
    
    # Initialize log settings dict with empty paths if none exist
    log_settings = {
        'apache_log_path': apache_log_path,
        'mysql_log_path': mysql_log_path,
        'log_retention': 30  # Default 30 days
    }
    
    # Get or initialize notification settings
    try:
        notification_prefs = NotificationPreference.objects.get(user=request.user)
        notification_settings = {
            'email_alerts': notification_prefs.email_alerts,
            'email_threshold': notification_prefs.email_threshold,
            'sms_alerts': notification_prefs.push_alerts,
            'slack_alerts': notification_prefs.in_app_alerts
        }
    except NotificationPreference.DoesNotExist:
        notification_settings = {
            'email_alerts': True,
            'email_threshold': 'high',
            'sms_alerts': False,
            'slack_alerts': False
        }
    
    # Get system and custom log paths
    from authentication.models import SystemSettings
    
    system_log_paths = '/var/log,C:\\Windows\\Logs'  # Default
    custom_log_paths = []
    
    try:
        # Get system log paths
        system_paths_setting = SystemSettings.objects.filter(
            section='logs', 
            settings_key='system_log_paths'
        ).first()
        
        if system_paths_setting and system_paths_setting.settings_value:
            paths_list = json.loads(system_paths_setting.settings_value)
            system_log_paths = ','.join(paths_list)
        
        # Get custom log paths
        custom_paths_setting = SystemSettings.objects.filter(
            section='logs', 
            settings_key='custom_log_paths'
        ).first()
        
        if custom_paths_setting and custom_paths_setting.settings_value:
            custom_log_paths = json.loads(custom_paths_setting.settings_value)
    except Exception as e:
        logger.error(f"Error loading log path settings: {str(e)}")
    
    # Update log_settings with the path information
    log_settings.update({
        'system_log_paths': system_log_paths,
        'custom_log_paths': custom_log_paths
    })
    
    # Build context
    context = {
        'user': request.user,
        'notification_settings': notification_settings,
        'log_settings': log_settings,
        'success_message': request.session.pop('success_message', None),
        'error_message': request.session.pop('error_message', None),
        'has_log_paths': bool(apache_log_path or mysql_log_path)  # Flag to indicate if any paths exist
    }
    
    return render(request, 'settings.html', context)


@login_required
@require_POST
def update_profile(request):
    """Handle profile update form submission"""
    try:
        # Get form data
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        
        # Debug logging
        logger.info(f"Updating profile for user {request.user.username}: {first_name} {last_name} {email}")
        
        # Update user object using Django's User model
        user = request.user
        user.first_name = first_name
        user.last_name = last_name
        user.email = email
        user.save()
        
        # Add confirmation message
        messages.success(request, "Profile updated successfully")
        request.session['success_message'] = "Profile updated successfully"
        
    except Exception as e:
        logger.error(f"Error updating profile: {str(e)}", exc_info=True)
        messages.error(request, f"Failed to update profile: {str(e)}")
        request.session['error_message'] = f"Failed to update profile: {str(e)}"
    
    return redirect('settings')


@login_required
@require_POST
def save_log_settings(request):
    """Handle log path settings form submission with improved file handling and analysis"""
    try:
        # Extract form data
        apache_log_path = request.POST.get('apache_log_path', '').strip()
        mysql_log_path = request.POST.get('mysql_log_path', '').strip()
        log_retention = int(request.POST.get('log_retention', 30))
        
        # Get system log paths (comma-separated)
        system_log_paths = request.POST.get('system_log_paths', '/var/log,C:\\Windows\\Logs').strip()
        system_log_paths_list = [path.strip() for path in system_log_paths.split(',') if path.strip()]
        
        # Get custom log paths from multi-value form field
        custom_log_paths = request.POST.getlist('custom_log_paths[]')
        custom_log_paths_list = [path.strip() for path in custom_log_paths if path.strip()]
        
        # Get client IP for audit logging
        client_ip = request.META.get('REMOTE_ADDR', None)
        
        # Check for existing Apache source to record change
        try:
            existing_apache = LogSource.objects.get(name='Apache Web Server')
            old_apache_path = existing_apache.file_path
        except LogSource.DoesNotExist:
            old_apache_path = None
            
        # Check for existing MySQL source to record change
        try:
            existing_mysql = LogSource.objects.get(name='MySQL Database Server')
            old_mysql_path = existing_mysql.file_path
        except LogSource.DoesNotExist:
            old_mysql_path = None
        
        # Save system and custom log paths (existing code)
        from authentication.models import SystemSettings
        
        # Save system log paths
        SystemSettings.objects.update_or_create(
            section='logs',
            settings_key='system_log_paths',
            defaults={
                'settings_value': json.dumps(system_log_paths_list),
                'last_updated': timezone.now(),
                'updated_by': request.user
            }
        )
        
        # Save custom log paths
        SystemSettings.objects.update_or_create(
            section='logs',
            settings_key='custom_log_paths',
            defaults={
                'settings_value': json.dumps(custom_log_paths_list),
                'last_updated': timezone.now(),
                'updated_by': request.user
            }
        )
        
        # Create media directory for file uploads
        media_root = getattr(settings, 'MEDIA_ROOT', os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'media'))
        logs_dir = os.path.join(media_root, 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        # Flag to track if we need to process logs
        files_processed = False
        
        # Process Apache log file upload
        if 'apache_log_file' in request.FILES and request.FILES['apache_log_file']:
            try:
                apache_file = request.FILES['apache_log_file']
                # Create a unique name based on timestamp and original filename
                original_name = os.path.basename(apache_file.name)
                safe_name = f"apache_{int(time.time())}_{original_name}"
                saved_path = os.path.join(logs_dir, safe_name)
                
                # Manual file save with proper error handling
                with open(saved_path, 'wb+') as destination:
                    for chunk in apache_file.chunks():
                        destination.write(chunk)
                
                # Use this path if successful
                apache_log_path = saved_path
                files_processed = True
                logger.info(f"Apache file saved to: {apache_log_path}")
            except Exception as e:
                logger.error(f"Failed to save Apache file: {str(e)}")
                # If upload fails but path is provided, keep the path
                if not apache_log_path and request.POST.get('apache_log_path'):
                    apache_log_path = request.POST.get('apache_log_path').strip()
        
        # Process MySQL log file upload
        if 'mysql_log_file' in request.FILES and request.FILES['mysql_log_file']:
            try:
                mysql_file = request.FILES['mysql_log_file']
                # Create a unique name based on timestamp and original filename
                original_name = os.path.basename(mysql_file.name)
                safe_name = f"mysql_{int(time.time())}_{original_name}"
                saved_path = os.path.join(logs_dir, safe_name)
                
                # Manual file save with proper error handling
                with open(saved_path, 'wb+') as destination:
                    for chunk in mysql_file.chunks():
                        destination.write(chunk)
                
                # Use this path if successful
                mysql_log_path = saved_path
                files_processed = True
                logger.info(f"MySQL file saved to: {mysql_log_path}")
            except Exception as e:
                logger.error(f"Failed to save MySQL file: {str(e)}")
                # If upload fails but path is provided, keep the path
                if not mysql_log_path and request.POST.get('mysql_log_path'):
                    mysql_log_path = request.POST.get('mysql_log_path').strip()
        
        # Validate log files
        if apache_log_path:
            apache_validation = validate_log_file(apache_log_path, 'apache')
            if not apache_validation['valid_log']:
                messages.warning(request, f"Apache log file may have issues: {apache_validation['error']}")

        if mysql_log_path:
            mysql_validation = validate_log_file(mysql_log_path, 'mysql')  
            if not mysql_validation['valid_log']:
                messages.warning(request, f"MySQL log file may have issues: {mysql_validation['error']}")

        # Don't update database if no paths are provided
        if not apache_log_path and not mysql_log_path:
            messages.error(request, "No log paths specified. Please enter at least one valid log file path.")
            request.session['error_message'] = "No log paths specified. Please enter at least one valid log file path."
            return redirect('settings')
        
        # Update database with non-empty paths only
        sources_to_process = []
        
        # For Apache
        if apache_log_path:
            apache_source, created = LogSource.objects.update_or_create(
                name='Apache Web Server',
                defaults={
                    'source_type': 'apache_access',
                    'file_path': apache_log_path,
                    'enabled': True,
                    'kafka_topic': 'apache_logs',
                    'use_filebeat': False
                }
            )
            if not created and hasattr(apache_source, 'created_at'):
                # Preserve the created_at timestamp for existing sources
                apache_source.created_at = LogSource.objects.get(id=apache_source.id).created_at
                apache_source.save(update_fields=['created_at'])
            
            sources_to_process.append(apache_source)
        
        # For MySQL
        if mysql_log_path:
            mysql_source, created = LogSource.objects.update_or_create(
                name='MySQL Database Server',
                defaults={
                    'source_type': 'mysql_error',
                    'file_path': mysql_log_path,
                    'enabled': True,
                    'kafka_topic': 'mysql_logs',
                    'use_filebeat': False
                }
            )
            if not created and hasattr(mysql_source, 'created_at'):
                # Preserve the created_at timestamp for existing sources
                mysql_source.created_at = LogSource.objects.get(id=mysql_source.id).created_at
                mysql_source.save(update_fields=['created_at'])
            
            sources_to_process.append(mysql_source)
        
        # Only process logs if files were uploaded or explicitly requested
        analysis_results = None
        if files_processed or request.POST.get('process_logs') == 'true':
            # Process and analyze the log files immediately for feedback
            log_count, threat_count = process_logs_from_sources(sources_to_process, request.user)
            
            # Provide specific feedback about the analysis
            if log_count > 0:
                if threat_count > 0:
                    analysis_msg = f"Analyzed {log_count} log entries and found {threat_count} potential security threats!"
                    messages.warning(request, analysis_msg)
                    request.session['warning_message'] = analysis_msg
                else:
                    analysis_msg = f"Analyzed {log_count} log entries. No immediate security threats detected."
                    messages.success(request, analysis_msg)
                    request.session['success_message'] = analysis_msg
            else:
                messages.info(request, "No log entries were found to analyze.")
        
        # Add confirmation message
        messages.success(request, "Log settings saved successfully")
        
        # Audit Apache log path change if path changed
        if apache_log_path and apache_log_path != old_apache_path and old_apache_path is not None:
            from authentication.models import ConfigAuditLog
            ConfigAuditLog.objects.create(
                user=request.user,
                change_type='apache_path',
                previous_value=old_apache_path,
                new_value=apache_log_path,
                description=f"Changed Apache log path from {old_apache_path} to {apache_log_path}",
                source_ip=client_ip
            )
            
        # Audit MySQL log path change if path changed
        if mysql_log_path and mysql_log_path != old_mysql_path and old_mysql_path is not None:
            from authentication.models import ConfigAuditLog
            ConfigAuditLog.objects.create(
                user=request.user,
                change_type='mysql_path',
                previous_value=old_mysql_path,
                new_value=mysql_log_path,
                description=f"Changed MySQL log path from {old_mysql_path} to {mysql_log_path}",
                source_ip=client_ip
            )
        
    except Exception as e:
        logger.error(f"Error saving log settings: {str(e)}", exc_info=True)
        messages.error(request, f"Failed to save log settings: {str(e)}")
        request.session['error_message'] = f"Failed to save log settings: {str(e)}"
    
    return redirect('settings')


@login_required
@require_POST
def change_password(request):
    """Handle password change form submission"""
    try:
        # Get form data
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        # Validate inputs
        user = request.user
        
        if not user.check_password(current_password):
            messages.error(request, "Current password is incorrect")
            request.session['error_message'] = "Current password is incorrect"
            return redirect('settings')
        
        if new_password != confirm_password:
            messages.error(request, "New passwords do not match")
            request.session['error_message'] = "New passwords do not match"
            return redirect('settings')
        
        if len(new_password) < 8:
            messages.error(request, "Password must be at least 8 characters long")
            request.session['error_message'] = "Password must be at least 8 characters long"
            return redirect('settings')
        
        # Update password
        user.set_password(new_password)
        user.save()
        
        # Update session to prevent logout
        update_session_auth_hash(request, user)
        
        messages.success(request, "Password changed successfully")
        request.session['success_message'] = "Password changed successfully"
        
    except Exception as e:
        logger.error(f"Error changing password: {str(e)}")
        messages.error(request, f"Failed to change password: {str(e)}")
        request.session['error_message'] = f"Failed to change password: {str(e)}"
    
    return redirect('settings')


@login_required
@require_POST
def save_notification_settings(request):
    """Handle notification settings form submission"""
    try:
        # Extract form data
        email_alerts = request.POST.get('email_alerts') == 'on'
        sms_alerts = request.POST.get('sms_alerts') == 'on'
        slack_alerts = request.POST.get('slack_alerts') == 'on'
        
        logger.info(f"Notification settings: email={email_alerts}, SMS={sms_alerts}, slack={slack_alerts}")
        
        # Get or create notification preferences
        prefs, created = NotificationPreference.objects.get_or_create(
            user=request.user,
            defaults={
                'email_alerts': email_alerts,
                'email_threshold': 'high',
                'push_alerts': sms_alerts,
                'push_threshold': 'critical',
                'in_app_alerts': slack_alerts,
                'in_app_threshold': 'medium',
                'created_at': timezone.now(),
                'updated_at': timezone.now(),
            }
        )
        
        # Update if not created
        if not created:
            prefs.email_alerts = email_alerts
            prefs.push_alerts = sms_alerts
            prefs.in_app_alerts = slack_alerts
            prefs.updated_at = timezone.now()
            prefs.save()
        
        messages.success(request, "Notification settings saved successfully")
        request.session['success_message'] = "Notification settings saved successfully"
        
    except Exception as e:
        logger.error(f"Error saving notification settings: {str(e)}")
        messages.error(request, f"Failed to save notification settings: {str(e)}")
        request.session['error_message'] = f"Failed to save notification settings: {str(e)}"
    
    return redirect('settings')


# Helper functions from your original code
def update_filebeat_config(apache_path, mysql_path):
    """Update Filebeat configuration to monitor the selected log files"""
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config', 'filebeat.yml')
    
    if not os.path.exists(config_path):
        logger.warning(f"Filebeat config not found at: {config_path}")
        return
    
    try:
        # Read current config
        with open(config_path, 'r') as f:
            config = f.read()
        
        # Replace paths
        new_config = re.sub(r'paths:\s*\n(\s+)-.*apache.*', f'paths:\n\\1- {apache_path.replace("\\", "/")}', config)
        new_config = re.sub(r'paths:\s*\n(\s+)-.*mysql.*', f'paths:\n\\1- {mysql_path.replace("\\", "/")}', new_config)
        
        # Write updated config
        with open(config_path, 'w') as f:
            f.write(new_config)
            
        logger.info(f"Updated Filebeat config at: {config_path}")
    except Exception as e:
        logger.error(f"Failed to update Filebeat config: {str(e)}")


def process_logs_from_sources(sources, current_user=None):
    """Process and analyze logs from specified sources without duplicate alerts"""
    if not sources:
        logger.warning("No sources provided to process_logs_from_sources")
        return 0, 0
        
    try:
        from threat_detection.rules import RuleEngine
        from django.utils import timezone
        import hashlib
        
        rule_engine = RuleEngine()
        threat_count = 0
        log_count = 0
        all_threats = []  # Track all detected threats for alerting
        ip_addresses = set()
        
        # Get the analysis timestamp for deduplication
        analysis_time = timezone.now()
        
        for source in sources:
            # Skip sources with invalid paths
            if not source.file_path or source.file_path == '.':
                logger.warning(f"Skipping source with invalid path: {source.name}")
                continue
                
            # Skip non-existent files
            if not os.path.exists(source.file_path):
                logger.warning(f"Log file not found at: {source.file_path}")
                continue
                
            # Open the file and read lines
            try:
                with open(source.file_path, 'r', encoding='utf-8', errors='replace') as file:
                    # Read all lines (or limit to a reasonable number)
                    lines = file.readlines()
                    logger.info(f"Read {len(lines)} lines from {source.file_path}")
            except Exception as file_error:
                logger.error(f"Error reading file {source.file_path}: {str(file_error)}")
                continue
                
            # Get the last known position
            try:
                position, created = LogFilePosition.objects.get_or_create(
                    source=source,
                    defaults={'position': 0}
                )
                
                # Only process new lines if we have a position
                if position.position > 0 and position.position < len(lines):
                    lines = lines[position.position:]
                    
                # Update position for next time
                position.position = len(lines)
                position.last_read = timezone.now()
                position.save()
                
            except Exception as pos_error:
                logger.warning(f"Error tracking file position: {str(pos_error)}")
                
            # Process each line
            for line_num, line in enumerate(lines[:100]):  # Limit to 100 lines for performance
                if line.strip():
                    try:
                        # Create raw log
                        raw_log = RawLog.objects.create(
                            source=source,
                            content=line.strip(),
                            timestamp=timezone.now(),
                            is_parsed=False
                        )
                        
                        # Parse the log
                        parsed_log = create_parsed_log_from_raw(raw_log)
                        
                        if parsed_log:
                            # Analyze for threats using rule engine
                            threats = rule_engine.analyze_log(parsed_log)
                            if threats:
                                all_threats.extend(threats)
                                threat_count += len(threats)
                                
                            log_count += 1
                            
                    except Exception as inner_e:
                        logger.error(f"Error processing log line {line_num}: {str(inner_e)}")
            
        # If threats were found, send a consolidated alert
        if all_threats:
            # Find highest severity
            severity = 'low'
            for threat in all_threats:
                if threat.source_ip:
                    ip_addresses.add(threat.source_ip)
                    
                if threat.severity == 'critical':
                    severity = 'critical'
                    break
                elif threat.severity == 'high' and severity != 'critical':
                    severity = 'high'
                elif threat.severity == 'medium' and severity not in ['critical', 'high']:
                    severity = 'medium'
            
            # Create a unique identifier for this batch of threats
            analysis_key = f"batch-{analysis_time.strftime('%Y%m%d%H%M')}-{','.join(sorted(ip_addresses)) if ip_addresses else 'no-ip'}"
            alert_id = int(hashlib.md5(analysis_key.encode()).hexdigest()[:8], 16) % 1000000
            
            # Extract some threat examples for the alert
            threat_examples = []
            for i, threat in enumerate(all_threats[:3]):  # Get first 3 threats for details
                threat_examples.append(f"{threat.rule.name if threat.rule else 'Unknown'} ({threat.severity})")
            
            # Send alert about batch analysis results
            from alerts.services import AlertService
            
            AlertService.send_alert(
                title=f"Log Analysis: {threat_count} security threats detected",
                message=f"Log analysis completed. Found {threat_count} security threats in {log_count} log entries.\n\n" +
                        f"Highest severity: {severity.upper()}\n\n" +
                        f"Examples: {', '.join(threat_examples)}\n\n" +
                        f"IP Addresses: {', '.join(ip_addresses) if ip_addresses else 'None'}\n\n" +
                        f"This alert was generated from manual log analysis.",
                severity=severity,
                threat_id=alert_id,  # Use our generated ID for deduplication
                source_ip=",".join(list(ip_addresses)[:5]) if ip_addresses else None,
                affected_system="Multiple systems",
                user=current_user  # Pass the current user here
            )
        
        return log_count, threat_count
                
    except Exception as e:
        logger.error(f"Error analyzing logs from sources: {str(e)}")
        return 0, 0


def create_parsed_log_from_raw(raw_log):
    """Create and return a ParsedLog from a RawLog with enhanced attack pattern detection"""
    import re
    from urllib.parse import unquote
    
    try:
        # Get source type safely
        source_type = raw_log.source.source_type if hasattr(raw_log, 'source') else ''
        
        # Get content
        log_content = raw_log.content
        
        # Decode URL-encoded content for better detection
        decoded_content = unquote(log_content)
        log_lower = decoded_content.lower()
        
        # Extract IP address
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_content)
        source_ip = ip_match.group(0) if ip_match else None
        
        # Extract HTTP method and URL path if present
        method_match = re.search(r'(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(/[^\s]*)', log_content)
        request_method = method_match.group(1) if method_match else None
        request_path = method_match.group(2) if method_match else None
        
        # Request parameters or POST data
        request_params = {}
        if 'login.php' in log_content:
            # Try to extract login parameters
            username_match = re.search(r'username=([^&\s]+)', log_content)
            password_match = re.search(r'password=([^&\s]+)', log_content)
            if username_match:
                request_params['username'] = unquote(username_match.group(1))
            if password_match:
                request_params['password'] = unquote(password_match.group(1))
        
        # Initialize threat detection data
        status = 'normal'
        threat_details = []
        attack_type = None
        attack_score = 0
        
        # =============================================
        # SQL INJECTION DETECTION - Enhanced patterns
        # =============================================
        sql_injection_patterns = [
            # Login bypass patterns
            r"'\s*OR\s*'?1'?\s*=\s*'?1", # 'OR '1'='1, 'OR 1=1
            r"'\s*OR\s*'1''='", # 'OR '1''='
            r"'\s*OR\s*.?1.?\s*=\s*.?1", # Various OR 1=1 variations
            r"--\s*$",  # SQL comment terminator
            r";--",     # Command termination with comment
            r"\/\*.*\*\/", # C-style comments
            
            # UNION-based injection
            r"UNION\s+(?:ALL\s+)?SELECT",
            r"UNION.*SELECT.*FROM",
            
            # Batch queries
            r";\s*(?:INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)",
            r"';\s*(?:INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)",
            
            # Database function calls
            r"(?:DATABASE|USER|CURRENT_USER|SYSTEM_USER|VERSION|@@version)\(\)",
            
            # Information schema access
            r"FROM\s+(?:information_schema|INFORMATION_SCHEMA)\.",
            r"SELECT\s+.*\s+FROM\s+(?:information_schema|INFORMATION_SCHEMA)",
            
            # Database exploration
            r"table_name\s+FROM\s+information_schema",
            r"column_name\s+FROM\s+information_schema",
            
            # Advanced SQL techniques
            r"CONCAT\([^)]*,[^)]*\)",  # CONCAT function typical in data extraction
            r"(?:CHAR|ASCII)\([0-9]+\)", # Char encoding to bypass filters
            r"LOAD_FILE\(['\"][^'\"]+['\"]\)", # File access attempt
            r"SLEEP\([0-9]+\)", # Time-based blind injection attempt
            r"BENCHMARK\([^)]+\)", # Another time-based technique
            r"UUID\(\)", # Used in SQLi debugging 
            r"SUBSTR\(|SUBSTRING\(", # String operations often used in blind SQLi
        ]
        
        # High severity SQL patterns - immediate threats
        critical_sql_patterns = [
            r"DROP\s+TABLE",
            r"DROP\s+DATABASE",
            r"DELETE\s+FROM\s+(?!logs|audit)", # Dangerous DELETE that's not targeting logs tables
            r"ALTER\s+TABLE.*(?:DROP|ADD)",
            r"INSERT\s+INTO\s+users",  # Attempts to insert users
            r"UPDATE\s+users\s+SET",   # Attempts to modify users
            r"TRUNCATE\s+TABLE",
            r";\s*SHUTDOWN"
        ]
        
        # =============================================
        # XSS DETECTION - Enhanced patterns
        # =============================================
        xss_patterns = [
            # Basic script tag patterns
            r"<script[^>]*>.*?<\/script>",
            r"<script[^>]*>[^<]*",  # Handles unclosed script tags
            
            # Event handler attributes
            r"on(?:load|click|mouseover|mouseout|mousedown|mouseup|submit|focus|blur|change|error)=",
            r"on[a-z]+\s*=\s*['\"](?:alert|confirm|prompt)\(",
            
            # Javascript URIs
            r"javascript:",
            r"data:text\/html",
            r"vbscript:",
            
            # DOM manipulation
            r"document\.(?:cookie|location|referrer|write|open)",
            r"window\.(?:location|open|localStorage|sessionStorage)",
            r"\.(?:innerHTML|outerHTML)\s*=",
            r"document\.createElement\(",
            r"\.appendChild\(",
            
            # Various tag-based XSS
            r"<img[^>]+src=[^>]+onerror=",
            r"<iframe[^>]+src=",
            r"<object[^>]+data=",
            r"<embed[^>]+src=",
            r"<svg[^>]+onload=",
            r"<math[^>]+xmlns=",
            r"<link[^>]+href=",
            r"<input[^>]+onfocus=",
            r"<div[^>]+onmouseover=",
            r"<body[^>]+onload=",
            r"<details[^>]+ontoggle=",
            r"<marquee[^>]+onstart=",
            
            # Unusual attribute combinations that might indicate evasion
            r"<[a-z]+[^>]*=['\"].*?['\"]\s*[^>]*=['\"].*?['\"]\s*on[a-z]+=",
            r"<[a-z]+[^>]*href=['\"](?!https?:)[^>]*>",
            r"<[a-z]+[^>]*src=['\"](?!https?:)[^>]*>"
        ]
        
        # =============================================
        # CSRF DETECTION - Look for suspicious referrers
        # =============================================
        csrf_patterns = [
            # Unusual form submissions without proper referer
            r"POST.*(?:profile|settings|password|email|config|admin).*Referer:\s*$",
            r"POST.*(?:profile|settings|password|email|config|admin).*Referer:\s*(?!https?:\/\/localhost)",
            # Form submissions from external domains
            r"POST.*?Referer:\s*https?:\/\/(?!localhost|your-domain)[^\s\/]+",
            # Missing CSRF token in requests that should have one
            r"POST.*?(?:profile|password|settings).*?(?!csrf)"
        ]
        
        # =============================================
        # DATA EXFILTRATION DETECTION
        # =============================================
        exfiltration_patterns = [
            # Sensitive data in query strings
            r"(?:password|passwd|pwd|pw|credentials|token|api[_-]?key)=",
            # Unusual amount of data in query strings
            r"\?.{100,}",
            # Data encodings that might hide stolen data
            r"base64[,:](?:[A-Za-z0-9+/]{30,}={0,2})",
            # Cookie theft via parameters
            r"\?.*?cookie=",
            # Unusual data formats being sent
            r"\?.*?data=(?:[A-Za-z0-9+/]{20,}={0,2})"
        ]
        
        # =============================================
        # SESSION HIJACKING DETECTION
        # =============================================
        session_patterns = [
            # Cookie theft patterns
            r"document\.cookie",
            r"fetch\(.*?\+document\.cookie\)",
            r"fetch\(.*?cookie=",
            r"new\s+Image\(.*?\+document\.cookie\)",
            # Session manipulation
            r"sessionStorage\.setItem\(",
            r"localStorage\.setItem\(",
            r"\?.*?(?:PHPSESSID|session_id|sid)=",
            # Suspicious cookie operations
            r"\.cookie\s*=\s*['\"][^'\"]+['\"]"
        ]
        
        # Command injection patterns
        command_injection_patterns = [
            r";\s*(?:/bin/|cmd\.exe|powershell|bash|sh\s)",
            r"\|\s*(?:cat|ls|dir|whoami|net\s+user|id|pwd)",
            r"`(?:[^`]+)`", # Backtick command execution
            r"\$\([^)]+\)", # Command substitution
            r"system\(['\"]", # PHP system function
            r"exec\(['\"]",  # PHP exec function
            r"shell_exec\(", # PHP shell_exec function
            r"passthru\(",   # PHP passthru function
            r"Runtime\.getRuntime\(\)\.exec\(" # Java runtime exec
        ]
        
        # Path traversal patterns
        path_traversal_patterns = [
            r"\.\.\/\.\.\/", # Basic directory traversal
            r"%2e%2e%2f",    # URL encoded traversal
            r"\.\.\\\.\.\\", # Windows path traversal
            r"(?:/etc/passwd|/etc/shadow|/proc/self|c:\\windows\\system32|boot\.ini)",
            r"file:///",     # Local file URL
            r"php://filter", # PHP stream filter
            r"zip://",       # PHP zip wrapper
            r"phar://"       # PHP phar wrapper
        ]
        
        # =============================================
        # PATTERN CHECKING IMPLEMENTATION
        # =============================================
        
        # Check for critical SQL injection patterns first - these warrant immediate flagging
        for pattern in critical_sql_patterns:
            if re.search(pattern, decoded_content, re.IGNORECASE):
                threat_details.append(f"Critical SQL injection detected: {pattern}")
                status = 'attack'
                attack_type = 'sql_injection'
                attack_score = 100  # Maximum score for critical patterns
                break
        
        # If not already marked as an attack, check for SQL injection patterns
        if status != 'attack':
            sql_matches = []
            for pattern in sql_injection_patterns:
                if re.search(pattern, decoded_content, re.IGNORECASE):
                    sql_matches.append(pattern)
                    attack_score += 15  # Increment score for each SQL pattern found
            
            if sql_matches:
                attack_type = 'sql_injection'
                for match in sql_matches[:3]:  # Limit to first 3 patterns to avoid overwhelming logs
                    threat_details.append(f"SQL injection pattern: {match}")
                
                # If multiple SQL patterns or certain login patterns, mark as attack
                if attack_score >= 30 or 'OR 1=1' in decoded_content:
                    status = 'attack'
                else:
                    status = 'suspicious'
        
        # Check for XSS patterns if not already a confirmed attack
        if attack_score < 80:  # Still check XSS even if SQL is suspected
            xss_matches = []
            for pattern in xss_patterns:
                if re.search(pattern, decoded_content, re.IGNORECASE):
                    xss_matches.append(pattern)
                    attack_score += 10  # XSS patterns add to the score
            
            if xss_matches and (attack_type is None or attack_score < 30):
                attack_type = 'xss'
                for match in xss_matches[:3]:
                    threat_details.append(f"XSS pattern: {match}")
                
                if attack_score >= 20 or len(xss_matches) >= 2:
                    status = 'attack' if status != 'attack' else status
                else:
                    status = 'suspicious' if status != 'attack' else status
        
        # Check for command injection
        if attack_score < 80:
            cmd_matches = []
            for pattern in command_injection_patterns:
                if re.search(pattern, decoded_content, re.IGNORECASE):
                    cmd_matches.append(pattern)
                    attack_score += 20  # Command injection is serious
            
            if cmd_matches:
                attack_type = attack_type or 'command_injection'
                for match in cmd_matches[:2]:
                    threat_details.append(f"Command injection pattern: {match}")
                status = 'attack'  # Command injection attempts are always attacks
        
        # Check for path traversal
        if attack_score < 80:
            path_matches = []
            for pattern in path_traversal_patterns:
                if re.search(pattern, decoded_content, re.IGNORECASE):
                    path_matches.append(pattern)
                    attack_score += 15
            
            if path_matches:
                attack_type = attack_type or 'path_traversal'
                for match in path_matches[:2]:
                    threat_details.append(f"Path traversal pattern: {match}")
                
                if attack_score >= 15 or len(path_matches) >= 1:
                    status = 'attack' if status != 'attack' else status
                else:
                    status = 'suspicious' if status != 'attack' else status
        
        # Check for CSRF if it's a form submission
        if request_method == "POST" and attack_score < 50:
            csrf_matches = []
            for pattern in csrf_patterns:
                if re.search(pattern, log_content, re.IGNORECASE):
                    csrf_matches.append(pattern)
                    attack_score += 5  # CSRF is typically lower scoring as it requires more context
            
            if csrf_matches:
                attack_type = attack_type or 'csrf'
                threat_details.append(f"Possible CSRF attempt: missing or invalid referer")
                status = 'suspicious' if status == 'normal' else status
        
        # Check for data exfiltration attempts
        if attack_score < 80:
            exfil_matches = []
            for pattern in exfiltration_patterns:
                if re.search(pattern, decoded_content, re.IGNORECASE):
                    exfil_matches.append(pattern)
                    attack_score += 10
            
            if exfil_matches:
                attack_type = attack_type or 'data_exfiltration'
                for match in exfil_matches[:2]:
                    threat_details.append(f"Possible data exfiltration: {match}")
                status = 'suspicious' if status == 'normal' else status
        
        # Check for session hijacking attempts
        if attack_score < 80:
            session_matches = []
            for pattern in session_patterns:
                if re.search(pattern, decoded_content, re.IGNORECASE):
                    session_matches.append(pattern)
                    attack_score += 15
            
            if session_matches:
                attack_type = attack_type or 'session_hijacking'
                for match in session_matches[:2]:
                    threat_details.append(f"Possible session hijacking: {match}")
                
                if 'document.cookie' in decoded_content and ('fetch(' in decoded_content or 'new Image(' in decoded_content):
                    status = 'attack'
                    attack_score += 30
                else:
                    status = 'suspicious' if status == 'normal' else status
        
        # Check specific vulnerable application endpoints mentioned in test scenarios
        if '/vuln_blog/' in log_content:
            vuln_endpoints = {
                'login.php': 'authentication',
                'search.php': 'information disclosure',
                'comments.php': 'data manipulation',
                'profile.php': 'account takeover'
            }
            
            for endpoint, risk_type in vuln_endpoints.items():
                if endpoint in log_content:
                    threat_details.append(f"Access to vulnerable endpoint: {endpoint} (risk: {risk_type})")
                    attack_score += 5
                    # Don't change status just for accessing endpoint, but track it
        
        # Final attack score adjustments based on multiple indicators
        if attack_score >= 50 and status != 'attack':
            status = 'attack'
        elif attack_score >= 20 and status == 'normal':
            status = 'suspicious'
        
        # Create normalized data with enhanced information
        normalized_data = {
            'content': log_content,
            'decoded_content': decoded_content,
            'message': log_content[:1000],
            'source_type': source_type,
            'source_ip': source_ip,
            'request_method': request_method,
            'request_path': request_path,
            'request_params': request_params,
            'analysis': {
                'suspicious_patterns': status != 'normal',
                'attack_score': attack_score,
                'attack_type': attack_type,
                'threat_details': threat_details,
                'time': timezone.now().isoformat()
            }
        }
        
        # Create a ParsedLog entry with enhanced security information
        parsed_log = ParsedLog.objects.create(
            raw_log=raw_log,
            timestamp=raw_log.timestamp,
            source_ip=source_ip,
            source_type=source_type,
            request_method=request_method,
            request_path=request_path,
            status=status,
            normalized_data=normalized_data,
            analyzed=True,
            analysis_time=timezone.now()
        )
        
        # Mark raw log as parsed
        raw_log.is_parsed = True
        raw_log.save(update_fields=['is_parsed'])
        
        # Log high-severity attacks for immediate attention
        if status == 'attack' and attack_score >= 80:
            logger.warning(
                f"HIGH SEVERITY ATTACK DETECTED: {attack_type} from {source_ip} - "
                f"Score: {attack_score}, Details: {', '.join(threat_details[:3])}"
            )
        
        return parsed_log
        
    except Exception as e:
        logger.error(f"Error creating parsed log: {str(e)}", exc_info=True)
        return None


def process_raw_logs_directly(limit=50):
    """Process raw logs without using the problematic parser factory"""
    import re
    from django.db.models import Q
    
    # Get raw logs that have is_parsed=False AND don't already have a ParsedLog
    raw_logs = RawLog.objects.filter(is_parsed=False).exclude(
        Q(id__in=ParsedLog.objects.values_list('raw_log_id', flat=True))
    ).order_by('-timestamp')[:limit]
    
    processed = 0
    skipped = 0
    
    for raw_log in raw_logs:
        try:
            with transaction.atomic():
                # Re-query the log inside the transaction to get a fresh copy
                fresh_log = RawLog.objects.select_for_update().get(id=raw_log.id)
                
                # Skip if already processed by another thread/process
                if fresh_log.is_parsed:
                    skipped += 1
                    continue
                    
                # First check if a ParsedLog already exists
                existing_parsed = ParsedLog.objects.filter(raw_log=fresh_log).first()
                if existing_parsed:
                    # Just update the is_parsed flag and skip creating a new entry
                    fresh_log.is_parsed = True
                    fresh_log.save(update_fields=['is_parsed'])
                    skipped += 1
                    continue
                
                # Get source type safely
                source_type = None
                if hasattr(fresh_log, 'source') and fresh_log.source:
                    source_type = fresh_log.source.source_type
                
                # Get content
                if hasattr(fresh_log, 'content') and fresh_log.content is not None:
                    log_content = fresh_log.content
                else:
                    log_content = str(fresh_log)
                
                # Extract IP address
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_content)
                source_ip = ip_match.group(0) if ip_match else None
                
                # Create a basic ParsedLog entry - using only fields from the database
                ParsedLog.objects.create(
                    raw_log=fresh_log,
                    timestamp=getattr(fresh_log, 'timestamp', timezone.now()),
                    source_ip=source_ip,
                    source_type=source_type or '',
                    status='normal',
                    normalized_data={
                        'content': log_content,
                        'message': log_content[:1000],
                        'source_type': source_type,
                        'source_ip': source_ip
                    },
                    analyzed=False
                )
                
                # Mark raw log as parsed
                fresh_log.is_parsed = True
                fresh_log.save(update_fields=['is_parsed'])
                processed += 1
                
        except Exception as e:
            logger.error(f"Error processing raw log {raw_log.id}: {str(e)}")
    
    return processed


@login_required
@require_POST
def test_log_paths(request):
    """API endpoint to test if log paths are valid and accessible"""
    try:
        data = json.loads(request.body)
        apache_path = data.get('apache_path')
        mysql_path = data.get('mysql_path')
        
        # Check Apache path
        apache_valid = os.path.isfile(apache_path) and os.access(apache_path, os.R_OK)
        
        # Check MySQL path
        mysql_valid = os.path.isfile(mysql_path) and os.access(mysql_path, os.R_OK)
        
        if apache_valid and mysql_valid:
            return JsonResponse({
                'success': True,
                'message': "Both log paths are valid and accessible."
            })
        elif apache_valid:
            return JsonResponse({
                'success': False,
                'error': "MySQL log path is not valid or not accessible."
            })
        elif mysql_valid:
            return JsonResponse({
                'success': False,
                'error': "Apache log path is not valid or not accessible."
            })
        else:
            return JsonResponse({
                'success': False,
                'error': "Neither log path is valid or accessible."
            })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': "Invalid request format. JSON required."
        }, status=400)
        
    except Exception as e:
        logger.error(f"Error testing log paths: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@require_POST
def analyze_logs_api(request):
    """API endpoint to trigger log analysis with threat detection."""
    try:
        # Extract logs_count parameter
        logs_count = 50  # Default value
        
        if request.headers.get('Content-Type') == 'application/json':
            try:
                if request.body:
                    data = json.loads(request.body)
                    logs_count = int(data.get('logs_count', logs_count))
            except (json.JSONDecodeError, ValueError):
                pass
        else:
            try:
                logs_count = int(request.POST.get('logs_count', logs_count))
            except ValueError:
                pass
        
        # Process logs
        processed_raw = process_raw_logs_directly(logs_count)
        
        # Count threats found in recently analyzed logs
        from django.utils import timezone
        from django.db.models import Q
        
        # Find logs analyzed in the last minute with suspicious or attack status
        one_minute_ago = timezone.now() - timedelta(minutes=1)
        suspicious_logs = ParsedLog.objects.filter(
            Q(analysis_time__gte=one_minute_ago) & 
            (Q(status='suspicious') | Q(status='attack'))
        ).order_by('-id')  # Use ID instead of timestamp to avoid the slice error
        
        threat_count = suspicious_logs.count()
        
        # If threats were found, create an alert
        if threat_count > 0:
            # Determine the highest severity
            severity_stats = {
                'attack': 0,
                'suspicious': 0
            }
            
            # Get details about first few threats for the alert
            threat_examples = []
            ip_addresses = set()
            
            for i, log in enumerate(suspicious_logs[:10]):  # Limit to first 10 for the message
                severity_stats[log.status] += 1
                if hasattr(log, 'source_ip') and log.source_ip:
                    ip_addresses.add(log.source_ip)
                
                if i < 3 and hasattr(log, 'request_path') and log.request_path:
                    threat_examples.append(f"{log.status.upper()} on path: {log.request_path[:50]}...")
            
            # Assign severity based on findings
            if severity_stats['attack'] > 0:
                severity = 'high'  # Attacks found - high severity
            else:
                severity = 'medium'  # Only suspicious - medium severity
            
            # Create a unique identifier for this batch of threats to avoid duplicates
            import hashlib
            alert_digest = hashlib.md5(f"{','.join(sorted(ip_addresses))}-{one_minute_ago.isoformat()}".encode()).hexdigest()
            
            # Send consolidated alert about found threats
            from alerts.services import AlertService
            
            AlertService.send_alert(
                title=f"Real-time Analysis: {threat_count} security concerns detected",
                message=(
                    f"Real-time analysis detected {severity_stats['attack']} attacks and "
                    f"{severity_stats['suspicious']} suspicious activities.\n\n"
                    f"IP Addresses involved: {', '.join(ip_addresses)}\n\n"
                    f"Examples:\n- " + "\n- ".join(threat_examples) + "\n\n"
                    f"These events occurred within the last minute and require investigation."
                ),
                severity=severity,
                threat_id=int(alert_digest[:8], 16) % 1000000,  # Generate pseudo ID from hash
                affected_system="Multiple systems",
                user=request.user  # Add this line to pass the current user
            )
        
        logger.info(f"Analyzed {processed_raw} logs, found {threat_count} potential threats")
        
        return JsonResponse({
            'success': True, 
            'logs_analyzed': processed_raw,
            'threats_found': threat_count,
            'message': f"Analyzed {processed_raw} logs. Found {threat_count} potential security threats."
        })
        
    except Exception as e:
        logger.error(f"Error in analyze_logs_api: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@require_POST
def start_real_time_analysis(request):
    """API endpoint to start or configure real-time analysis."""
    try:
        data = json.loads(request.body)
        interval = int(data.get('interval', 30))
        logs_count = int(data.get('logs_count', 50))
        enabled = data.get('enabled', True)
        
        # Get the singleton instance
        processor = RealtimeLogProcessor.get_instance()
        
        if enabled:
            # Start or reconfigure real-time analysis
            success = processor.start(interval=interval, logs_count=logs_count)
            status = "started" if success else "failed"
        else:
            # Stop real-time analysis
            processor.stop()
            status = "stopped"
        
        return JsonResponse({
            'success': True,
            'status': status,
            'interval': interval,
            'logs_count': logs_count
        })
        
    except Exception as e:
        logger.error(f"Error configuring real-time analysis: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)


@login_required
@require_POST
def debug_log_sources(request):
    """Debug API to get information about all log sources"""
    try:
        sources = LogSource.objects.all()
        source_data = []
        
        for source in sources:
            file_exists = False
            file_readable = False
            file_size = 0
            
            if source.file_path:
                file_exists = os.path.exists(source.file_path)
                if file_exists:
                    try:
                        file_readable = os.access(source.file_path, os.R_OK)
                        file_size = os.path.getsize(source.file_path)
                    except:
                        pass
            
            source_data.append({
                'id': source.id,
                'name': source.name,
                'type': source.source_type,
                'path': source.file_path,
                'file_exists': file_exists,
                'file_readable': file_readable,
                'file_size': file_size,
                'enabled': source.enabled,
            })
        
        return JsonResponse({
            'success': True,
            'sources': source_data
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
def clean_log_sources(request):
    """API to clean up log sources with problematic paths"""
    try:
        # Find invalid log sources (those with '.' as path)
        invalid_sources = LogSource.objects.filter(file_path='.')
        count = invalid_sources.count()
        
        # Delete them
        invalid_sources.delete()
        
        # Return current valid sources
        valid_sources = LogSource.objects.all()
        source_data = []
        
        for source in valid_sources:
            source_data.append({
                'id': source.id,
                'name': source.name,
                'file_path': source.file_path
            })
        
        return JsonResponse({
            'success': True,
            'message': f"Database cleaned. Removed entries with '.' paths. {valid_sources.count()} sources remain.",
            'sources': source_data
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)