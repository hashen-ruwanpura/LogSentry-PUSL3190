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

# Configure logger
logger = logging.getLogger(__name__)


class RealtimeLogProcessor:
    """Singleton class to manage real-time log processing"""
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self.running = False
        self.interval = 30  # Default interval in seconds
        self.logs_count = 50  # Default number of logs to analyze
        self._thread = None

    @classmethod
    def get_instance(cls):
        """Get the singleton instance"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def start(self, interval=30, logs_count=50):
        """Start or reconfigure the real-time analysis"""
        if self._thread and self._thread.is_alive():
            # Stop existing thread first
            self.running = False
            self._thread.join(timeout=2.0)

        # Update configuration
        self.interval = max(10, min(300, interval))  # Between 10 and 300 seconds
        self.logs_count = max(10, min(500, logs_count))  # Between 10 and 500 logs
        self.running = True

        # Start new thread
        self._thread = threading.Thread(target=self._process_loop)
        self._thread.daemon = True
        self._thread.start()
        
        return True

    def stop(self):
        """Stop the real-time analysis"""
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None

    def _process_loop(self):
        """Main processing loop"""
        while self.running:
            try:
                process_raw_logs_directly(self.logs_count)
                
                # Sleep for the interval
                for _ in range(self.interval):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in real-time log processing: {str(e)}")
                time.sleep(5)


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
        
        # Save system and custom log paths to settings
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
            log_count, threat_count = process_logs_from_sources(sources_to_process)
            
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


def process_logs_from_sources(sources):
    """Process and analyze logs from specified sources immediately"""
    if not sources:
        logger.warning("No sources provided to process_logs_from_sources")
        return
        
    try:
        from threat_detection.rules import RuleEngine
        rule_engine = RuleEngine()
        threat_count = 0
        log_count = 0
        
        for source in sources:
            # Skip sources with invalid paths
            if not source.file_path or source.file_path == '.':
                logger.warning(f"Skipping source with invalid path: {source.name}")
                continue
                
            # Skip non-existent files
            if not os.path.exists(source.file_path):
                logger.warning(f"Log file not found at: {source.file_path}")
                continue
                
            try:
                # Ensure the file is readable
                if not os.access(source.file_path, os.R_OK):
                    logger.warning(f"Log file not readable: {source.file_path}")
                    continue
                
                # Get file size for tracking
                current_size = os.path.getsize(source.file_path)
                
                # Get or create file position record
                try:
                    position, created = LogFilePosition.objects.get_or_create(
                        source=source,
                        file_path=source.file_path,
                        defaults={'position': 0, 'last_updated': timezone.now()}
                    )
                    
                    # If file was truncated or replaced, reset position
                    if position.position > current_size:
                        position.position = 0
                except Exception as e:
                    logger.error(f"Error getting file position record: {str(e)}")
                
                # Read the log file
                with open(source.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                # Process each line (up to 100 lines)
                for line_num, line in enumerate(lines[:100]):
                    if line.strip():
                        try:
                            # Create raw log entry
                            raw_log = RawLog.objects.create(
                                source=source,
                                content=line.strip(),
                                timestamp=timezone.now(),
                                is_parsed=False,
                                processing_status='new'
                            )
                            
                            # Immediately parse and analyze the log
                            parsed_log = create_parsed_log_from_raw(raw_log)
                            
                            if parsed_log:
                                # Analyze for threats using rule engine
                                threats = rule_engine.analyze_log(parsed_log)
                                if threats:
                                    # Update status if threats found
                                    parsed_log.status = 'suspicious' if len(threats) == 1 else 'attack'
                                    parsed_log.normalized_data['threats'] = [str(t) for t in threats]
                                    parsed_log.save(update_fields=['status', 'normalized_data'])
                                    
                                    threat_count += len(threats)
                                
                                log_count += 1
                            
                        except Exception as inner_e:
                            logger.error(f"Error processing log line {line_num}: {str(inner_e)}")
                
                logger.info(f"Analyzed {log_count} log entries from: {source.file_path}, found {threat_count} threats")
                
                # Update position record
                try:
                    position.position = current_size
                    position.last_updated = timezone.now()
                    position.save()
                except Exception as e:
                    logger.error(f"Error updating file position: {str(e)}")
                
            except Exception as e:
                logger.error(f"Error analyzing log file {source.file_path}: {str(e)}")
                
        return log_count, threat_count
                
    except Exception as e:
        logger.error(f"Error analyzing logs from sources: {str(e)}")
        return 0, 0


def create_parsed_log_from_raw(raw_log):
    """Create and return a ParsedLog from a RawLog with basic analysis"""
    import re
    
    try:
        # Get source type safely
        source_type = raw_log.source.source_type if hasattr(raw_log, 'source') else ''
        
        # Get content
        log_content = raw_log.content
        
        # Extract IP address
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_content)
        source_ip = ip_match.group(0) if ip_match else None
        
        # Check for common attack patterns
        status = 'normal'
        patterns = [
            'union select.*from', 
            'exec\\s*\\(', 
            'eval\\s*\\(', 
            '<script>.*</script>', 
            'select.*from.*where.*=.*--',
            '../../',
            'etc/passwd'
        ]
        high_severity_patterns = ['union select.*from', 'exec\\s*\\(', 'eval\\s*\\(']
        medium_severity_patterns = ['<script>.*</script>', 'select.*from.*where.*=.*--']
        low_severity_patterns = ['../../', 'etc/passwd']
        
        # High severity patterns
        if any(pattern in log_content.lower() for pattern in high_severity_patterns):
            status = 'attack'
        # Medium severity patterns
        elif any(pattern in log_content.lower() for pattern in medium_severity_patterns):
            status = 'suspicious'
        # Low severity patterns - just log, don't alert
        elif any(pattern in log_content.lower() for pattern in low_severity_patterns):
            status = 'unusual'
        
        # For example, only flag 'password' if it appears near suspicious terms
        if 'password' in log_content.lower() and any(term in log_content.lower() for term in ['failed', 'incorrect', 'invalid', 'attempt']):
            # More likely to be a real issue
            status = 'suspicious'
        
        # Create a ParsedLog entry
        parsed_log = ParsedLog.objects.create(
            raw_log=raw_log,
            timestamp=raw_log.timestamp,
            source_ip=source_ip,
            source_type=source_type,
            status=status,
            normalized_data={
                'content': log_content,
                'message': log_content[:1000],
                'source_type': source_type,
                'source_ip': source_ip,
                'analysis': {
                    'suspicious_patterns': bool(status == 'suspicious'),
                    'time': timezone.now().isoformat()
                }
            },
            analyzed=True,
            analysis_time=timezone.now()
        )
        
        # Mark raw log as parsed
        raw_log.is_parsed = True
        raw_log.save(update_fields=['is_parsed'])
        
        return parsed_log
        
    except Exception as e:
        logger.error(f"Error creating parsed log: {str(e)}")
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
        threats = ParsedLog.objects.filter(
            Q(analysis_time__gte=one_minute_ago) & 
            (Q(status='suspicious') | Q(status='attack'))
        ).count()
        
        logger.info(f"Analyzed {processed_raw} logs, found {threats} potential threats")
        
        return JsonResponse({
            'success': True, 
            'logs_analyzed': processed_raw,
            'threats_found': threats,
            'message': f"Analyzed {processed_raw} logs. Found {threats} potential security threats."
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