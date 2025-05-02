import os
import json
import logging
import threading
import time
from datetime import datetime, timedelta

from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.conf import settings
from django.contrib import messages
from django.core.files.storage import FileSystemStorage

from log_ingestion.models import LogSource, RawLog, ParsedLog
from log_ingestion.collectors import LogFileHandler
from threat_detection.analyzer import ThreatAnalyzer
from threat_detection.models import Threat, DetectionRule

logger = logging.getLogger(__name__)

# Global variable to store analysis thread
analysis_thread = None
stop_analysis = False

@login_required
def settings_view(request):
    """Main settings view handling multiple forms and tabs"""
    context = {}
    success_message = None
    error_message = None
    user = request.user
    
    # Handle log configuration form submission
    if request.method == 'POST' and 'log_path_settings' in request.POST:
        success_message, error_message = handle_log_settings(request)
    
    # Handle real-time analysis settings
    elif request.method == 'POST' and 'realtime_settings' in request.POST:
        success_message, error_message = handle_realtime_settings(request)
    
    # Get current log settings
    log_settings = get_log_settings()
    
    # Get real-time analysis settings
    realtime_settings = get_realtime_settings()
    
    # Get analysis status
    analysis_status = is_analysis_running()
    
    # Combine all context
    context = {
        'user': user,
        'log_settings': log_settings,
        'realtime_settings': realtime_settings,
        'analysis_status': analysis_status,
        'success_message': success_message or request.GET.get('success'),
        'error_message': error_message or request.GET.get('error')
    }
    
    return render(request, 'settings.html', context)

def get_log_settings():
    """Get current log path settings from database"""
    try:
        log_settings = {}
        
        # Get Apache log source
        apache_source = LogSource.objects.filter(source_type='apache').first()
        if apache_source:
            log_settings['apache_log_path'] = apache_source.file_path
        else:
            log_settings['apache_log_path'] = os.path.join(settings.BASE_DIR, 'logs', 'apache', 'access.log')
            
        # Get MySQL log source
        mysql_source = LogSource.objects.filter(source_type='mysql').first()
        if mysql_source:
            log_settings['mysql_log_path'] = mysql_source.file_path
        else:
            log_settings['mysql_log_path'] = os.path.join(settings.BASE_DIR, 'logs', 'mysql', 'mysql.log')
        
        # Get log retention period (from system settings if available)
        try:
            from authentication.models import SystemSettings
            log_retention = SystemSettings.get_setting('backup', 'apacheLogRetention', 30)
            log_settings['log_retention'] = log_retention
        except (ImportError, Exception):
            log_settings['log_retention'] = 30
            
        return log_settings
    except Exception as e:
        logger.error(f"Error getting log settings: {str(e)}")
        return {
            'apache_log_path': os.path.join(settings.BASE_DIR, 'logs', 'apache', 'access.log'),
            'mysql_log_path': os.path.join(settings.BASE_DIR, 'logs', 'mysql', 'mysql.log'),
            'log_retention': 30
        }

def handle_log_settings(request):
    """Handle log configuration form submission"""
    try:
        apache_log_path = request.POST.get('apache_log_path', '').strip()
        mysql_log_path = request.POST.get('mysql_log_path', '').strip()
        log_retention = int(request.POST.get('log_retention', 30))
        
        # Store original paths before validation for fallback
        original_apache_path = apache_log_path
        original_mysql_path = mysql_log_path
        
        # Validate paths but don't override user's selection on failure
        apache_valid, apache_error = validate_log_path(apache_log_path)
        mysql_valid, mysql_error = validate_log_path(mysql_log_path)
        
        # If invalid, show error but don't change the path
        validation_errors = []
        if not apache_valid:
            validation_errors.append(f"Apache log path may have issues: {apache_error}")
        if not mysql_valid:
            validation_errors.append(f"MySQL log path may have issues: {mysql_error}")
            
        # Only warn about validation errors, but still save the paths as specified
        if validation_errors:
            logger.warning(f"Saving log paths with warnings: {', '.join(validation_errors)}")
        
        # Handle file uploads if present - these take priority over path fields
        if 'apache_log_file' in request.FILES:
            upload_path = handle_file_upload(request.FILES['apache_log_file'], 'apache')
            if upload_path:  # Only use if upload was successful
                apache_log_path = upload_path
        
        if 'mysql_log_file' in request.FILES:
            upload_path = handle_file_upload(request.FILES['mysql_log_file'], 'mysql')
            if upload_path:  # Only use if upload was successful
                mysql_log_path = upload_path
        
        # Ensure we're using the original paths if nothing else worked
        if not apache_log_path:
            apache_log_path = original_apache_path
        if not mysql_log_path:
            mysql_log_path = original_mysql_path
        
        # Create or update log sources with the final paths
        apache_source, created = LogSource.objects.update_or_create(
            source_type='apache',
            defaults={
                'name': 'Apache Logs',
                'file_path': apache_log_path,
                'enabled': True,
                'kafka_topic': 'raw_logs',
                'use_filebeat': False
            }
        )
        
        mysql_source, created = LogSource.objects.update_or_create(
            source_type='mysql',
            defaults={
                'name': 'MySQL Logs',
                'file_path': mysql_log_path,
                'enabled': True,
                'kafka_topic': 'raw_logs',
                'use_filebeat': False
            }
        )
        
        # Update settings
        try:
            from authentication.models import SystemSettings
            SystemSettings.set_setting('backup', 'apacheLogRetention', log_retention, request.user)
            SystemSettings.set_setting('backup', 'mysqlLogRetention', log_retention, request.user)
        except (ImportError, Exception) as e:
            logger.warning(f"Could not save log retention setting: {str(e)}")
        
        # Restart log monitoring
        try:
            from log_ingestion.realtime_processor import RealtimeLogProcessor
            processor = RealtimeLogProcessor.get_instance()
            processor.stop_processing()
            processor.start_processing()
            logger.info("Log monitoring restarted with new configuration")
        except Exception as e:
            logger.error(f"Error restarting log monitoring: {str(e)}")
        
        return "Log configuration saved successfully", ", ".join(validation_errors) if validation_errors else None
        
    except Exception as e:
        logger.error(f"Error saving log settings: {str(e)}")
        return None, f"Error saving log configuration: {str(e)}"

def handle_file_upload(file_obj, log_type):
    """Handle uploaded log files"""
    try:
        # Create appropriate directory in media folder
        upload_dir = os.path.join(settings.MEDIA_ROOT, 'logs', log_type)
        os.makedirs(upload_dir, exist_ok=True)
        
        # Use Django's file storage to save the file
        fs = FileSystemStorage(location=upload_dir)
        filename = fs.save(file_obj.name, file_obj)
        
        # Return the full path to the saved file
        return os.path.join(upload_dir, filename)
    except Exception as e:
        logger.error(f"Error handling file upload: {str(e)}")
        return None

def validate_log_path(path):
    """Validate if a log path is accessible and valid"""
    # Check if path is empty
    if not path:
        return False, "Path cannot be empty"
    
    # Special handling for development or server paths
    if path.startswith('/var/log') and os.name == 'nt':
        # For Windows development, we'll be lenient with Linux paths
        return True, None
        
    if path.startswith('C:') and os.name != 'nt':
        # For Linux servers, we'll be lenient with Windows paths
        return True, None
    
    # Check if directory exists and is accessible
    log_dir = os.path.dirname(path)
    if not os.path.exists(log_dir):
        try:
            # Try to create the directory
            os.makedirs(log_dir, exist_ok=True)
            logger.info(f"Created directory: {log_dir}")
        except Exception as e:
            return False, f"Directory does not exist and could not be created: {str(e)}"
    
    # Check if we can create/access the file
    try:
        # If file doesn't exist, try to create an empty one
        if not os.path.exists(path):
            with open(path, 'w') as f:
                pass  # Just create the file
            logger.info(f"Created empty log file: {path}")
        
        # Check that we can open the file for reading
        with open(path, 'r'):
            pass  # Just check if we can open it
            
        return True, None
    except PermissionError:
        return False, "Permission denied. Check file permissions."
    except FileNotFoundError:
        return False, "File not found and could not be created."
    except Exception as e:
        return False, str(e)

@login_required
@require_POST
@csrf_exempt
def test_log_paths(request):
    """API endpoint to test if log paths are accessible"""
    try:
        data = json.loads(request.body)
        apache_path = data.get('apache_path', '')
        mysql_path = data.get('mysql_path', '')
        
        # Test Apache log path
        apache_valid, apache_error = validate_log_path(apache_path)
        
        # Test MySQL log path
        mysql_valid, mysql_error = validate_log_path(mysql_path)
        
        if apache_valid and mysql_valid:
            return JsonResponse({
                'success': True,
                'message': 'Both log paths are valid and accessible.'
            })
        else:
            errors = []
            if not apache_valid:
                errors.append(f"Apache log: {apache_error}")
            if not mysql_valid:
                errors.append(f"MySQL log: {mysql_error}")
                
            return JsonResponse({
                'success': False,
                'error': ' '.join(errors)
            })
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request'
        }, status=400)
    except Exception as e:
        logger.error(f"Error testing log paths: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@require_POST
@csrf_exempt
def validate_file_path(request):
    """API endpoint to validate a file path without changing settings"""
    try:
        data = json.loads(request.body)
        file_path = data.get('path', '')
        
        path_exists = os.path.exists(file_path)
        is_file = os.path.isfile(file_path)
        is_readable = False
        
        if path_exists and is_file:
            try:
                with open(file_path, 'r') as f:
                    # Try to read first few bytes
                    f.read(10)
                is_readable = True
            except:
                is_readable = False
        
        # If path doesn't exist, check if we can create it
        can_create = False
        if not path_exists:
            try:
                directory = os.path.dirname(file_path)
                can_create = os.access(directory, os.W_OK) if os.path.exists(directory) else False
            except:
                can_create = False
        
        return JsonResponse({
            'success': True,
            'path_exists': path_exists,
            'is_file': is_file,
            'is_readable': is_readable,
            'can_create': can_create,
            'is_valid': path_exists and is_file and is_readable or can_create
        })
        
    except Exception as e:
        logger.error(f"Error validating file path: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

def get_realtime_settings():
    """Get current real-time analysis settings"""
    try:
        settings = {
            'analysis_interval': 30,  # Default: 30 seconds
            'logs_per_analysis': 50,  # Default: 50 logs per run
            'enabled': True,          # Default: enabled
            'last_run': None
        }
        
        # Try to get settings from system settings if available
        try:
            from authentication.models import SystemSettings
            analysis_interval = SystemSettings.get_setting('analysis', 'interval', 30)
            logs_per_analysis = SystemSettings.get_setting('analysis', 'logsCount', 50)
            analysis_enabled = SystemSettings.get_setting('analysis', 'enabled', True)
            last_run = SystemSettings.get_setting('analysis', 'lastRun', None)
            
            settings['analysis_interval'] = analysis_interval
            settings['logs_per_analysis'] = logs_per_analysis
            settings['enabled'] = analysis_enabled
            settings['last_run'] = last_run
        except (ImportError, Exception) as e:
            logger.warning(f"Could not get real-time analysis settings from SystemSettings: {str(e)}")
        
        return settings
    except Exception as e:
        logger.error(f"Error getting real-time analysis settings: {str(e)}")
        return {
            'analysis_interval': 30,
            'logs_per_analysis': 50,
            'enabled': True,
            'last_run': None
        }

def handle_realtime_settings(request):
    """Handle real-time analysis settings form submission"""
    try:
        # Get form data
        analysis_interval = max(10, min(300, int(request.POST.get('analysis_interval', 30))))
        logs_per_analysis = max(10, min(500, int(request.POST.get('logs_per_analysis', 50))))
        enabled = request.POST.get('enable_realtime') == 'on'
        
        # Save settings
        try:
            from authentication.models import SystemSettings
            SystemSettings.set_setting('analysis', 'interval', analysis_interval, request.user)
            SystemSettings.set_setting('analysis', 'logsCount', logs_per_analysis, request.user)
            SystemSettings.set_setting('analysis', 'enabled', enabled, request.user)
        except (ImportError, Exception) as e:
            logger.warning(f"Could not save analysis settings to SystemSettings: {str(e)}")
        
        # Handle the real-time analysis thread
        if enabled:
            start_real_time_analysis(analysis_interval, logs_per_analysis)
        else:
            stop_real_time_analysis()
        
        return "Real-time analysis settings saved successfully", None
    except ValueError:
        return None, "Invalid values for analysis interval or logs per analysis"
    except Exception as e:
        logger.error(f"Error saving real-time analysis settings: {str(e)}")
        return None, f"Error saving analysis settings: {str(e)}"

def is_analysis_running():
    """Check if analysis is currently running"""
    global analysis_thread
    return analysis_thread is not None and analysis_thread.is_alive()

def start_real_time_analysis(interval, logs_count):
    """Start a background thread for real-time log analysis"""
    global analysis_thread, stop_analysis
    
    # Stop any existing analysis thread
    stop_real_time_analysis()
    
    # Create and start a new thread
    stop_analysis = False
    analysis_thread = threading.Thread(
        target=real_time_analysis_worker, 
        args=(interval, logs_count),
        daemon=True
    )
    analysis_thread.start()
    
    logger.info(f"Started real-time analysis thread with interval {interval}s and {logs_count} logs per run")
    
    return True

def stop_real_time_analysis():
    """Stop the background thread for real-time log analysis"""
    global analysis_thread, stop_analysis
    
    if analysis_thread and analysis_thread.is_alive():
        stop_analysis = True
        # Wait for thread to terminate gracefully
        analysis_thread.join(timeout=5.0)
        logger.info("Stopped real-time analysis thread")
        
    analysis_thread = None
    stop_analysis = False
    
    return True

def real_time_analysis_worker(interval, logs_count):
    """Worker thread function for real-time log analysis"""
    global stop_analysis
    
    logger.info(f"Real-time analysis worker started: interval={interval}s, logs={logs_count}")
    
    while not stop_analysis:
        try:
            # Process any new raw logs first
            processed_raw = process_unprocessed_raw_logs(logs_count)
            
            # Get unanalyzed logs and analyze them
            unanalyzed_logs = ParsedLog.objects.filter(analyzed=0).order_by('-timestamp')[:logs_count]
            
            if unanalyzed_logs:
                # Initialize analyzer
                analyzer = ThreatAnalyzer()
                threats_found = 0
                logs_analyzed = 0
                
                # Process each log
                for log in unanalyzed_logs:
                    try:
                        found_threats = analyzer.analyze_log(log)
                        logs_analyzed += 1
                        
                        if found_threats:
                            threats_found += len(found_threats)
                        
                        # Mark as analyzed
                        log.analyzed = 1
                        log.analysis_time = timezone.now()
                        log.save(update_fields=['analyzed', 'analysis_time'])
                    except Exception as e:
                        logger.error(f"Error analyzing log {log.id}: {str(e)}")
                
                if logs_analyzed > 0:
                    logger.info(f"Real-time analysis: {logs_analyzed} logs analyzed, {threats_found} threats found")
            
            # Update last run timestamp
            try:
                from authentication.models import SystemSettings
                SystemSettings.set_setting('analysis', 'lastRun', timezone.now().isoformat())
            except Exception as e:
                logger.error(f"Error updating last run timestamp: {str(e)}")
                
        except Exception as e:
            logger.error(f"Error in real-time analysis worker: {str(e)}")
        
        # Sleep for the specified interval
        for _ in range(interval):
            if stop_analysis:
                break
            time.sleep(1)
    
    logger.info("Real-time analysis worker stopped")

def process_unprocessed_raw_logs(logs_count=50):
    """Process raw logs that haven't been parsed yet"""
    try:
        # Get raw logs that need parsing
        unprocessed_logs = RawLog.objects.filter(is_parsed=False)[:logs_count]
        
        if not unprocessed_logs.exists():
            return 0
        
        processed_count = 0
        from log_ingestion.parsers import LogParserFactory
        
        for raw_log in unprocessed_logs:
            try:
                source_type = raw_log.source.source_type
                parser = LogParserFactory.get_parser(source_type)
                
                if parser:
                    parser.parse(raw_log)
                    processed_count += 1
                else:
                    logger.warning(f"No parser found for log type: {source_type}")
                    # Mark as processed anyway to avoid repeated attempts
                    raw_log.is_parsed = True
                    raw_log.processing_status = 'no_parser'
                    raw_log.save(update_fields=['is_parsed', 'processing_status'])
                    
            except Exception as e:
                logger.error(f"Error parsing raw log {raw_log.id}: {str(e)}")
                # Mark as error but processed
                raw_log.is_parsed = True
                raw_log.processing_status = 'error'
                raw_log.save(update_fields=['is_parsed', 'processing_status'])
        
        return processed_count
        
    except Exception as e:
        logger.error(f"Error processing unprocessed raw logs: {str(e)}")
        return 0

@login_required
@require_POST
@csrf_exempt
def analyze_logs_api(request):
    """API endpoint to analyze logs manually"""
    try:
        data = json.loads(request.body)
        logs_count = int(data.get('logs_count', 50))
        
        # Run analysis
        threats_found, logs_analyzed = analyze_logs(logs_count)
        
        # Update last run timestamp
        try:
            from authentication.models import SystemSettings
            SystemSettings.set_setting('analysis', 'lastRun', timezone.now().isoformat())
        except Exception:
            pass
        
        return JsonResponse({
            'success': True,
            'logs_analyzed': logs_analyzed,
            'threats_found': threats_found
        })
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request'
        }, status=400)
    except Exception as e:
        logger.error(f"Error analyzing logs: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

def analyze_logs(logs_count):
    """Analyze the most recent logs for threats"""
    try:
        # Get the most recent unanalyzed logs
        unanalyzed_logs = ParsedLog.objects.filter(
            analyzed=0
        ).select_related('raw_log').order_by('-timestamp')[:logs_count]
        
        # Initialize threat analyzer
        analyzer = ThreatAnalyzer()
        
        # Track number of threats found
        threats_found = 0
        
        # Process each log
        for log in unanalyzed_logs:
            try:
                # Analyze the log
                found_threats = analyzer.analyze_log(log)
                
                # Count threats found
                if found_threats:
                    threats_found += len(found_threats)
                
                # Mark as analyzed
                log.analyzed = 1
                log.analysis_time = timezone.now()
                log.save(update_fields=['analyzed', 'analysis_time'])
                
            except Exception as e:
                logger.error(f"Error analyzing log {log.id}: {str(e)}")
                # Mark as errored but still processed
                log.analyzed = -1  # Error code
                log.save(update_fields=['analyzed'])
        
        logger.info(f"Analyzed {len(unanalyzed_logs)} logs, found {threats_found} threats")
        
        return threats_found, len(unanalyzed_logs)
        
    except Exception as e:
        logger.error(f"Error in log analysis: {str(e)}")
        return 0, 0

@login_required
@require_POST
@csrf_exempt
def run_analysis_now(request):
    """API endpoint to run analysis immediately"""
    try:
        # Get real-time analysis settings
        settings = get_realtime_settings()
        
        # Run analysis
        threats_found, logs_analyzed = analyze_logs(settings['logs_per_analysis'])
        
        # Update last run timestamp
        try:
            from authentication.models import SystemSettings
            SystemSettings.set_setting('analysis', 'lastRun', timezone.now().isoformat())
        except Exception:
            pass
        
        return JsonResponse({
            'success': True,
            'message': f"Analysis completed: analyzed {logs_analyzed} logs, found {threats_found} threats",
            'threats_found': threats_found,
            'logs_analyzed': logs_analyzed,
            'timestamp': timezone.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error running analysis: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@require_POST
@csrf_exempt
def toggle_analysis(request):
    """API endpoint to toggle real-time analysis on/off"""
    try:
        data = json.loads(request.body)
        enabled = data.get('enabled', False)
        
        settings = get_realtime_settings()
        
        if enabled:
            start_real_time_analysis(settings['analysis_interval'], settings['logs_per_analysis'])
            message = "Real-time analysis started"
        else:
            stop_real_time_analysis()
            message = "Real-time analysis stopped"
        
        # Save setting
        try:
            from authentication.models import SystemSettings
            SystemSettings.set_setting('analysis', 'enabled', enabled, request.user)
        except Exception:
            pass
        
        return JsonResponse({
            'success': True,
            'message': message,
            'enabled': enabled,
            'is_running': is_analysis_running()
        })
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request'
        }, status=400)
    except Exception as e:
        logger.error(f"Error toggling analysis: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@csrf_exempt
def get_analysis_status(request):
    """API endpoint to get current analysis status"""
    try:
        settings = get_realtime_settings()
        running = is_analysis_running()
        
        return JsonResponse({
            'success': True,
            'settings': settings,
            'is_running': running,
            'current_time': timezone.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting analysis status: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@require_POST
@csrf_exempt
def force_analyze_all_logs(request):
    """Force analysis of all logs regardless of previous analysis status"""
    try:
        # Count of logs to process
        logs_count = int(request.POST.get('logs_count', 100))
        
        # First, process any raw logs that haven't been parsed
        processed_raw_logs = process_unprocessed_raw_logs(logs_count)
        
        # Then reset analysis status on parsed logs
        ParsedLog.objects.all().update(analyzed=0)
        
        # Get logs for processing
        logs = ParsedLog.objects.filter(analyzed=0).select_related('raw_log').order_by('-timestamp')[:logs_count]
        
        if not logs.exists():
            return JsonResponse({
                'success': True,
                'message': f"Processed {processed_raw_logs} raw logs but found no logs to analyze",
                'threats_found': 0,
                'logs_analyzed': 0
            })
        
        # Initialize analyzer
        analyzer = ThreatAnalyzer()
        threats_found = 0
        logs_analyzed = 0
        
        # Process each log
        for log in logs:
            try:
                found_threats = analyzer.analyze_log(log)
                logs_analyzed += 1
                
                if found_threats:
                    threats_found += len(found_threats)
                    logger.info(f"Found {len(found_threats)} threats in log {log.id}")
                
                # Mark as analyzed
                log.analyzed = 1
                log.analysis_time = timezone.now()
                log.save(update_fields=['analyzed', 'analysis_time'])
            except Exception as e:
                logger.error(f"Error analyzing log {log.id}: {str(e)}")
                # Mark as error
                log.analyzed = -1
                log.save(update_fields=['analyzed'])
        
        return JsonResponse({
            'success': True,
            'message': f"Force analysis completed: {logs_analyzed} logs analyzed, {threats_found} threats found",
            'threats_found': threats_found,
            'logs_analyzed': logs_analyzed
        })
        
    except Exception as e:
        logger.error(f"Error in force analysis: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@require_POST
@csrf_exempt
def generate_test_logs(request):
    """Generate test logs with known threat patterns for testing"""
    try:
        # Create Apache test logs
        apache_test_logs = [
            '192.168.1.100 - - [01/May/2025:10:00:00 +0000] "GET /login.php HTTP/1.1" 200 2267',
            '192.168.1.101 - - [01/May/2025:10:01:00 +0000] "POST /login.php HTTP/1.1" 200 1453',
            '192.168.1.102 - - [01/May/2025:10:02:00 +0000] "GET /admin.php HTTP/1.1" 403 1189',
            # SQL injection attempt
            '192.168.1.103 - - [01/May/2025:10:03:00 +0000] "GET /products.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 3821',
            # Directory traversal attempt
            '192.168.1.104 - - [01/May/2025:10:04:00 +0000] "GET /../../../../etc/passwd HTTP/1.1" 404 1567',
            # XSS attempt
            '192.168.1.105 - - [01/May/2025:10:05:00 +0000] "GET /search.php?q=<script>alert(\'XSS\')</script> HTTP/1.1" 200 2145'
        ]
        
        # Create MySQL test logs
        mysql_test_logs = [
            '2025-05-01T10:00:00.000001Z 13 [Warning] Access denied for user \'root\'@\'localhost\' (using password: YES)',
            '2025-05-01T10:01:00.000001Z 14 [Note] Server hostname (bind-address): \'*\'; port: 3306',
            '2025-05-01T10:02:00.000001Z 15 [Note] IPv6 is available.',
            # Suspicious query
            '2025-05-01T10:03:00.000001Z 16 [Warning] Slow query: SELECT * FROM users WHERE username = \'admin\' OR 1=1; -- \'',
            # Root login attempt
            '2025-05-01T10:04:00.000001Z 17 [Warning] Root login attempt from 192.168.1.110',
            # Database error
            '2025-05-01T10:05:00.000001Z 18 [ERROR] Fatal error: Cant open and lock privilege tables: Table \'mysql.user\' doesn\'t exist'
        ]
        
        # Get log sources
        apache_source = LogSource.objects.filter(source_type='apache').first()
        mysql_source = LogSource.objects.filter(source_type='mysql').first()
        
        if not apache_source or not mysql_source:
            return JsonResponse({
                'success': False, 
                'error': 'Log sources not configured correctly'
            }, status=400)
        
        # Store Apache test logs
        for line in apache_test_logs:
            RawLog.objects.create(
                source=apache_source,
                content=line,
                timestamp=timezone.now(),
                is_parsed=False,
                processing_status='new'
            )
            
        # Store MySQL test logs
        for line in mysql_test_logs:
            RawLog.objects.create(
                source=mysql_source,
                content=line,
                timestamp=timezone.now(),
                is_parsed=False,
                processing_status='new'
            )
        
        return JsonResponse({
            'success': True,
            'message': f"Generated {len(apache_test_logs)} Apache logs and {len(mysql_test_logs)} MySQL logs"
        })
        
    except Exception as e:
        logger.error(f"Error generating test logs: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@csrf_exempt
def debug_log_status(request):
    """API endpoint to get debug information about logs"""
    try:
        raw_logs_count = RawLog.objects.count()
        parsed_logs_count = ParsedLog.objects.count()
        unprocessed_raw_logs = RawLog.objects.filter(is_parsed=False).count()
        unanalyzed_parsed_logs = ParsedLog.objects.filter(analyzed=0).count()
        analyzed_logs = ParsedLog.objects.filter(analyzed=1).count()
        error_logs = ParsedLog.objects.filter(analyzed=-1).count()
        
        # Get counts by source type
        apache_raw = RawLog.objects.filter(source__source_type='apache').count()
        mysql_raw = RawLog.objects.filter(source__source_type='mysql').count()
        
        apache_parsed = ParsedLog.objects.filter(source_type='apache').count()
        mysql_parsed = ParsedLog.objects.filter(source_type='mysql').count()
        
        # Get counts of threats
        from threat_detection.models import Threat
        threats_count = Threat.objects.count()
        
        # Check rules
        from threat_detection.models import DetectionRule
        active_rules = DetectionRule.objects.filter(enabled=True).count()
        
        return JsonResponse({
            'success': True,
            'stats': {
                'raw_logs_total': raw_logs_count,
                'parsed_logs_total': parsed_logs_count,
                'unprocessed_raw_logs': unprocessed_raw_logs,
                'unanalyzed_parsed_logs': unanalyzed_parsed_logs,
                'analyzed_logs': analyzed_logs,
                'error_logs': error_logs,
                'apache_raw': apache_raw,
                'mysql_raw': mysql_raw,
                'apache_parsed': apache_parsed,
                'mysql_parsed': mysql_parsed,
                'threats_detected': threats_count,
                'active_rules': active_rules
            }
        })
    except Exception as e:
        logger.error(f"Error getting log stats: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@require_POST
@csrf_exempt
def import_threat_test_logs(request):
    """Import test logs with known security threats for testing detection"""
    try:
        log_type = request.POST.get('log_type', 'both')
        
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        test_logs_dir = os.path.join(base_dir, 'test_logs')
        
        if not os.path.exists(test_logs_dir):
            os.makedirs(test_logs_dir)
            
        # Track stats
        apache_logs_imported = 0
        mysql_logs_imported = 0
        
        # Import Apache logs
        if log_type in ['both', 'apache']:
            apache_log_path = os.path.join(test_logs_dir, 'apache_threats.log')
            
            # Create the test Apache log file if it doesn't exist
            if not os.path.exists(apache_log_path):
                with open(apache_log_path, 'w') as f:
                    f.write("""192.168.1.100 - - [02/May/2025:10:00:00 +0000] "GET /login.php HTTP/1.1" 200 2267 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.101 - - [02/May/2025:10:01:00 +0000] "POST /login.php HTTP/1.1" 200 1453 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# SQL Injection Attempts
192.168.1.103 - - [02/May/2025:10:03:00 +0000] "GET /products.php?id=1' OR '1'='1 HTTP/1.1" 200 3821 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.103 - - [02/May/2025:10:04:00 +0000] "GET /search.php?query=1' UNION SELECT username,password FROM users -- HTTP/1.1" 200 4231 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Directory Traversal Attempts
192.168.1.104 - - [02/May/2025:10:05:00 +0000] "GET /../../../../etc/passwd HTTP/1.1" 404 1567 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.104 - - [02/May/2025:10:06:00 +0000] "GET /download.php?file=../../../config.php HTTP/1.1" 200 1892 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# XSS Attempts
192.168.1.105 - - [02/May/2025:10:07:00 +0000] "GET /search.php?q=<script>alert('XSS')</script> HTTP/1.1" 200 2145 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.105 - - [02/May/2025:10:08:00 +0000] "POST /comment.php HTTP/1.1" 200 1876 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "<img src='x' onerror='alert(document.cookie)'>"

# Brute Force Attempts (Multiple failed logins)
192.168.1.106 - - [02/May/2025:10:09:00 +0000] "POST /admin/login.php HTTP/1.1" 401 1122 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.106 - - [02/May/2025:10:09:10 +0000] "POST /admin/login.php HTTP/1.1" 401 1122 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Suspicious User Agent
192.168.1.107 - - [02/May/2025:10:10:00 +0000] "GET / HTTP/1.1" 200 4589 "-" "Nikto/2.1.6"
192.168.1.107 - - [02/May/2025:10:10:10 +0000] "GET / HTTP/1.1" 200 4589 "-" "sqlmap/1.4.9"

# Command Injection Attempts
192.168.1.108 - - [02/May/2025:10:11:00 +0000] "GET /ping.php?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1" 200 2341 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
""")
            
            # Get Apache LogSource
            apache_source = LogSource.objects.filter(source_type='apache').first()
            if not apache_source:
                apache_source = LogSource.objects.create(
                    name='Apache Logs',
                    source_type='apache',
                    file_path=apache_log_path,
                    enabled=True
                )
            
            # Import the logs
            try:
                with open(apache_log_path, 'r') as f:
                    for line in f:
                        # Skip comments and empty lines
                        if line.strip() and not line.strip().startswith('#'):
                            # Store as raw log
                            try:
                                hash_value = hashlib.md5(line.encode()).hexdigest()
                                # Check for duplicate
                                if not RawLog.objects.filter(content__startswith=line[:50]).exists():
                                    raw_log = RawLog.objects.create(
                                        source=apache_source,
                                        content=line.strip(),
                                        timestamp=timezone.now(),
                                        is_parsed=False,
                                        processing_status='new'
                                    )
                                    apache_logs_imported += 1
                            except Exception as e:
                                logger.error(f"Error importing Apache log: {str(e)}")
            except Exception as e:
                logger.error(f"Error reading Apache test log file: {str(e)}")
        
        # Import MySQL logs
        if log_type in ['both', 'mysql']:
            mysql_log_path = os.path.join(test_logs_dir, 'mysql_threats.log')
            
            # Create the test MySQL log file if it doesn't exist
            if not os.path.exists(mysql_log_path):
                with open(mysql_log_path, 'w') as f:
                    f.write("""2025-05-02T10:00:00.000001Z 13 [Note] Server started, ready to accept connections
2025-05-02T10:01:00.000001Z 14 [Note] Server hostname (bind-address): '*'; port: 3306

# Failed Login Attempts
2025-05-02T10:03:00.000001Z 16 [Warning] Access denied for user 'root'@'localhost' (using password: YES)
2025-05-02T10:03:10.000001Z 17 [Warning] Access denied for user 'admin'@'192.168.1.110' (using password: NO)
2025-05-02T10:03:20.000001Z 18 [Warning] Access denied for user 'root'@'192.168.1.110' (using password: YES)

# Suspicious SQL Queries
2025-05-02T10:04:00.000001Z 21 [Warning] Slow query: SELECT * FROM users WHERE username = 'admin' OR 1=1; -- '
2025-05-02T10:04:10.000001Z 22 [Note] Slow query: SELECT * FROM users WHERE username LIKE '%' UNION SELECT username,password FROM admin_users -- %'
2025-05-02T10:04:20.000001Z 23 [Note] Query: LOAD DATA INFILE '/etc/passwd' INTO TABLE temp

# Privilege Escalation Attempts
2025-05-02T10:05:00.000001Z 24 [Warning] User 'web_user'@'localhost' attempted GRANT ALL PRIVILEGES command without sufficient privileges

# Database Structure Tampering
2025-05-02T10:06:00.000001Z 26 [Warning] User 'web_user'@'localhost' attempted to DROP DATABASE 'production'

# Excessive Connection Attempts
2025-05-02T10:07:00.000001Z 28 [Warning] Too many connections from 192.168.1.120
2025-05-02T10:07:10.000001Z 29 [Warning] Too many connections from 192.168.1.120

# Error Messages That Reveal Information
2025-05-02T10:08:00.000001Z 31 [ERROR] Failed to open file '/var/lib/mysql/mysql-bin.00001', errno: 13
""")
            
            # Get MySQL LogSource
            mysql_source = LogSource.objects.filter(source_type='mysql').first()
            if not mysql_source:
                mysql_source = LogSource.objects.create(
                    name='MySQL Logs',
                    source_type='mysql',
                    file_path=mysql_log_path,
                    enabled=True
                )
            
            # Import the logs
            try:
                with open(mysql_log_path, 'r') as f:
                    for line in f:
                        # Skip comments and empty lines
                        if line.strip() and not line.strip().startswith('#'):
                            # Store as raw log
                            try:
                                # Check for duplicate
                                if not RawLog.objects.filter(content__startswith=line[:50]).exists():
                                    raw_log = RawLog.objects.create(
                                        source=mysql_source,
                                        content=line.strip(),
                                        timestamp=timezone.now(),
                                        is_parsed=False,
                                        processing_status='new'
                                    )
                                    mysql_logs_imported += 1
                            except Exception as e:
                                logger.error(f"Error importing MySQL log: {str(e)}")
            except Exception as e:
                logger.error(f"Error reading MySQL test log file: {str(e)}")
        
        # Process all imported logs
        process_unprocessed_raw_logs(100)
        
        return JsonResponse({
            'success': True,
            'message': f"Imported {apache_logs_imported} Apache logs and {mysql_logs_imported} MySQL logs with security threats",
            'apache_logs': apache_logs_imported,
            'mysql_logs': mysql_logs_imported
        })
        
    except Exception as e:
        logger.error(f"Error importing threat test logs: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

# Initialize the real-time analysis thread when server starts
def initialize_analysis():
    """Initialize the real-time analysis when server starts"""
    try:
        settings = get_realtime_settings()
        
        if settings['enabled']:
            start_real_time_analysis(settings['analysis_interval'], settings['logs_per_analysis'])
            logger.info("Started real-time analysis thread on server initialization")
    except Exception as e:
        logger.error(f"Error initializing real-time analysis: {str(e)}")

# Call initialize on module import
initialize_analysis()
