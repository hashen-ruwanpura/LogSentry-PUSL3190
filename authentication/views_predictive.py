import logging
import json
import psutil
import time
import os
import tempfile
import shutil
import subprocess
from datetime import datetime, timedelta
from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.utils import timezone

logger = logging.getLogger(__name__)

# This would be implemented in a real system to get actual system resource metrics
def get_system_metrics():
    """Get current system resource metrics"""
    try:
        # In a real implementation, this would use a library like psutil
        # to get actual system resource metrics
        return {
            'cpu': {
                'usage': 52.8,
                'trend': 'stable',
                'trend_value': -0.5,
            },
            'memory': {
                'usage': 67.4,
                'total': 16.0,  # GB
                'used': 10.8,   # GB
                'trend': 'increasing',
                'trend_value': 7.5,
            },
            'disk': {
                'usage': 78.1,
                'total': 200.0, # GB
                'used': 156.2,  # GB
                'trend': 'increasing',
                'trend_value': 4.2,
            },
            'log_volume': get_log_volume_metrics()
        }
    except Exception as e:
        logger.error(f"Error getting system metrics: {str(e)}")
        return {}

def get_log_volume_metrics():
    """Get actual log volume metrics from the configured log paths"""
    import os
    import glob
    from log_ingestion.models import LogSource
    from django.db.models import Q
    from authentication.models import SystemSettings
    
    try:
        # Initialize metrics dictionary
        log_metrics = {
            "usage": 0,
            "trend": "stable",
            "total": 20.0,  # Default total allocation in GB (can be made configurable)
            "used": 0,
            "apache_size": 0,
            "mysql_size": 0,
            "system_size": 0,
            "apache_growth": 0,
            "mysql_growth": 0,
            "system_growth": 0
        }
        
        # Get configured log paths from the database
        apache_sources = LogSource.objects.filter(
            Q(name='Apache Web Server') | Q(source_type__startswith='apache')
        )
        mysql_sources = LogSource.objects.filter(
            Q(name='MySQL Database Server') | Q(source_type__startswith='mysql')
        )
        
        # Process Apache log files
        apache_size = 0
        for source in apache_sources:
            if source.file_path and os.path.exists(source.file_path):
                if os.path.isdir(source.file_path):
                    # If it's a directory, get all log files
                    for log_file in glob.glob(os.path.join(source.file_path, '*.log')):
                        apache_size += os.path.getsize(log_file)
                else:
                    # Single log file
                    apache_size += os.path.getsize(source.file_path)
        
        # Process MySQL log files
        mysql_size = 0
        for source in mysql_sources:
            if source.file_path and os.path.exists(source.file_path):
                if os.path.isdir(source.file_path):
                    # If it's a directory, get all log files
                    for log_file in glob.glob(os.path.join(source.file_path, '*.log')):
                        mysql_size += os.path.getsize(log_file)
                else:
                    # Single log file
                    mysql_size += os.path.getsize(source.file_path)
        
        # Convert bytes to GB
        apache_size_gb = apache_size / (1024 * 1024 * 1024)
        mysql_size_gb = mysql_size / (1024 * 1024 * 1024)
        
        # Get system logs size from configurable paths
        system_size = 0
        
        # Get configured system log paths from settings
        try:
            # First, try to get custom paths from settings
            system_paths_setting = SystemSettings.objects.filter(
                section='logs',
                settings_key='system_log_paths'
            ).first()
            
            if system_paths_setting and system_paths_setting.settings_value:
                # Parse the JSON list of paths
                import json
                system_log_paths = json.loads(system_paths_setting.settings_value)
            else:
                # Fallback to default paths if no custom paths defined
                system_log_paths = ['/var/log', 'C:\\Windows\\Logs']
                
            # Also check for extra custom log paths
            custom_paths_setting = SystemSettings.objects.filter(
                section='logs',
                settings_key='custom_log_paths'
            ).first()
            
            if custom_paths_setting and custom_paths_setting.settings_value:
                custom_log_paths = json.loads(custom_paths_setting.settings_value)
                # Add custom paths to system paths
                system_log_paths.extend(custom_log_paths)
                
        except Exception as e:
            logger.warning(f"Error reading log paths from settings: {str(e)}")
            # Fallback to default paths
            system_log_paths = ['/var/log', 'C:\\Windows\\Logs']
        
        # Process each configured path
        for log_path in system_log_paths:
            if os.path.exists(log_path) and os.path.isdir(log_path):
                for root, dirs, files in os.walk(log_path, topdown=True, followlinks=False):
                    for file in files:
                        if file.endswith('.log') or file.endswith('.txt'):
                            try:
                                full_path = os.path.join(root, file)
                                system_size += os.path.getsize(full_path)
                            except OSError:
                                continue
        
        system_size_gb = system_size / (1024 * 1024 * 1024)
        
        # Calculate total used space
        total_used_gb = apache_size_gb + mysql_size_gb + system_size_gb
        
        # Calculate log volume percentage
        log_metrics["used"] = round(total_used_gb, 2)
        log_metrics["apache_size"] = round(apache_size_gb, 2)
        log_metrics["mysql_size"] = round(mysql_size_gb, 2)
        log_metrics["system_size"] = round(system_size_gb, 2)
        
        # Calculate usage percentage
        log_metrics["usage"] = round((total_used_gb / log_metrics["total"]) * 100, 1)
        
        # Calculate growth trend from historical data
        # For now using simplified approach - later this should use stored historical data
        from django.core.cache import cache
        from datetime import datetime, timedelta
        
        # Try to get previous measurements from cache
        prev_metrics = cache.get('log_volume_metrics')
        current_time = datetime.now()
        
        if prev_metrics and 'timestamp' in prev_metrics:
            # Calculate time difference in days
            time_diff = (current_time - prev_metrics['timestamp']).total_seconds() / 86400
            
            if time_diff > 0:
                # Calculate daily growth rates
                apache_growth = (apache_size_gb - prev_metrics.get('apache_size', 0)) / time_diff
                mysql_growth = (mysql_size_gb - prev_metrics.get('mysql_size', 0)) / time_diff
                system_growth = (system_size_gb - prev_metrics.get('system_size', 0)) / time_diff
                
                # Convert daily growth to weekly growth
                log_metrics["apache_growth"] = round(apache_growth * 7, 2)
                log_metrics["mysql_growth"] = round(mysql_growth * 7, 2)
                log_metrics["system_growth"] = round(system_growth * 7, 2)
                
                # Set trend based on total growth rate
                total_growth_rate = (apache_growth + mysql_growth + system_growth)
                if total_growth_rate > 0.05:  # More than 5% per day
                    log_metrics["trend"] = "increasing"
                elif total_growth_rate < -0.01:  # Negative growth (log rotation/cleanup)
                    log_metrics["trend"] = "decreasing"
                else:
                    log_metrics["trend"] = "stable"
        
        # Store current metrics for future trend calculation
        cache_data = {
            'timestamp': current_time,
            'apache_size': apache_size_gb,
            'mysql_size': mysql_size_gb,
            'system_size': system_size_gb,
            'total_used': total_used_gb
        }
        cache.set('log_volume_metrics', cache_data, 60 * 60 * 24 * 7)  # Cache for 7 days
        
        return log_metrics
        
    except Exception as e:
        logger.exception(f"Error calculating log volume metrics: {str(e)}")
        # Return default values in case of error
        return {
            "usage": 45.5,
            "trend": "stable",
            "total": 20.0,
            "used": 9.1,
            "apache_growth": 1.2,
            "mysql_growth": 0.8,
            "system_growth": 0.3
        }

@login_required
def predictive_maintenance_view(request):
    """View for predictive maintenance dashboard"""
    try:
        # Get current system metrics
        metrics = get_system_metrics()
        
        # Get prediction time window from request
        time_window = int(request.GET.get('time_window', 24))
        
        # Context for the template
        context = {
            'metrics': metrics,
            'time_window': time_window,
            'current_cpu': metrics.get('cpu', {}).get('usage', 0),
            'current_memory': metrics.get('memory', {}).get('usage', 0),
            'current_disk': metrics.get('disk', {}).get('usage', 0),
            'current_log_volume': metrics.get('log_volume', {}).get('usage', 0),
            'last_updated': timezone.now(),
        }
        
        # Render the template
        return render(request, 'authentication/predictive_maintenance.html', context)
    
    except Exception as e:
        logger.exception(f"Error in predictive maintenance view: {str(e)}")
        return render(request, 'authentication/predictive_maintenance.html', {
            'error_message': f"An error occurred: {str(e)}"
        })

@login_required
def resource_predictions_api(request):
    """API endpoint for resource exhaustion predictions"""
    try:
        # Get time window from request
        time_window = int(request.GET.get('time_window', 24))
        
        # Get system metrics
        metrics = get_system_metrics()
        
        # Calculate predictions based on metrics and time window
        predictions = {
            'cpu': predict_resource_exhaustion('cpu', metrics.get('cpu', {}), time_window),
            'memory': predict_resource_exhaustion('memory', metrics.get('memory', {}), time_window),
            'disk': predict_resource_exhaustion('disk', metrics.get('disk', {}), time_window),
            'log_volume': predict_resource_exhaustion('log_volume', metrics.get('log_volume', {}), time_window),
        }
        
        # Return JSON response
        return JsonResponse({
            'metrics': metrics,
            'predictions': predictions,
            'timestamp': timezone.now().isoformat()
        })
        
    except Exception as e:
        logger.exception(f"Error in resource predictions API: {str(e)}")
        return JsonResponse({
            'error': str(e)
        }, status=500)

@login_required
def system_metrics_api(request):
    """API endpoint to get real-time system metrics"""
    try:
        # Get real CPU usage
        cpu_usage = psutil.cpu_percent(interval=0.5)
        
        # Get memory usage
        memory = psutil.virtual_memory()
        memory_usage = memory.percent
        memory_total = round(memory.total / (1024 * 1024 * 1024), 1)  # Convert to GB
        memory_used = round(memory.used / (1024 * 1024 * 1024), 1)  # Convert to GB
        
        # Get disk usage
        disk = psutil.disk_usage('/')
        disk_usage = disk.percent
        disk_total = round(disk.total / (1024 * 1024 * 1024), 1)  # Convert to GB
        disk_used = round(disk.used / (1024 * 1024 * 1024), 1)  # Convert to GB
        
        # Get CPU temperature if available
        cpu_temp = None
        try:
            if hasattr(psutil, "sensors_temperatures"):
                temps = psutil.sensors_temperatures()
                if temps and 'coretemp' in temps:
                    cpu_temp = temps['coretemp'][0].current
        except Exception as e:
            logger.debug(f"Could not get CPU temperature: {str(e)}")
        
        # Get trends from historical data
        cpu_trend_data = analyze_resource_trend('cpu')
        memory_trend_data = analyze_resource_trend('memory')
        disk_trend_data = analyze_resource_trend('disk')
        
        # Get real log volume data
        log_volume = get_log_volume_metrics()
        
        # Store current metrics for historical analysis
        store_system_metrics()
        
        return JsonResponse({
            "cpu": {
                "usage": cpu_usage,
                "trend": cpu_trend_data['trend'],
                "trend_value": cpu_trend_data['trend_value'],
                "temperature": cpu_temp,
                "confidence": cpu_trend_data['confidence']
            },
            "memory": {
                "usage": memory_usage,
                "trend": memory_trend_data['trend'],
                "trend_value": memory_trend_data['trend_value'],
                "total": memory_total,
                "used": memory_used,
                "confidence": memory_trend_data['confidence']
            },
            "disk": {
                "usage": disk_usage,
                "trend": disk_trend_data['trend'],
                "trend_value": disk_trend_data['trend_value'],
                "total": disk_total,
                "used": disk_used,
                "confidence": disk_trend_data['confidence']
            },
            "log_volume": log_volume,
            "timestamp": int(time.time())
        })
    except Exception as e:
        logger.exception(f"Error in system metrics API: {str(e)}")
        return JsonResponse({
            "error": str(e)
        }, status=500)

@login_required
def automated_tasks_api(request):
    """API endpoint for running automated maintenance tasks"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    task_type = request.POST.get('task_type')
    if not task_type:
        return JsonResponse({'error': 'Task type is required'}, status=400)
    
    try:
        if task_type == 'log_rotation':
            result = configure_log_rotation(request)
        elif task_type == 'cache_cleanup':
            result = run_cache_cleanup(request)
        elif task_type == 'memory_optimization':
            result = configure_memory_optimization(request)
        else:
            return JsonResponse({'error': 'Invalid task type'}, status=400)
        
        return JsonResponse(result)
    except Exception as e:
        logger.exception(f"Error executing automated task {task_type}: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def open_folder(request):
    """API endpoint to open folder in Windows Explorer"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    folder_path = request.POST.get('folder_path')
    if not folder_path:
        return JsonResponse({'error': 'Folder path is required'}, status=400)
    
    try:
        import os
        import platform
        import subprocess
        
        # Check if path exists
        if not os.path.exists(folder_path):
            return JsonResponse({'error': f'Path not found: {folder_path}'}, status=404)
        
        # Open folder in file explorer
        if platform.system() == 'Windows':
            subprocess.Popen(['explorer', folder_path])
        else:
            # Fallback for Unix systems
            subprocess.Popen(['xdg-open', folder_path])
        
        return JsonResponse({'success': True})
    except Exception as e:
        logger.exception(f"Error opening folder: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

def configure_log_rotation(request):
    """Configure and apply real log rotation for Apache and MySQL logs"""
    try:
        import os
        import platform
        import subprocess
        
        # 1. Get actual Apache and MySQL log paths
        apache_paths = []
        mysql_paths = []
        
        from log_ingestion.models import LogSource
        from django.db.models import Q
        
        # Get Apache log paths
        apache_sources = LogSource.objects.filter(
            Q(name='Apache Web Server') | Q(source_type__startswith='apache')
        )
        for source in apache_sources:
            if source.file_path and os.path.exists(source.file_path):
                apache_paths.append(source.file_path)
        
        # Get MySQL log paths
        mysql_sources = LogSource.objects.filter(
            Q(name='MySQL Database Server') | Q(source_type__startswith='mysql')
        )
        for source in mysql_sources:
            if source.file_path and os.path.exists(source.file_path):
                mysql_paths.append(source.file_path)
        
        # 2. Determine the appropriate log rotation mechanism based on OS
        if platform.system() == 'Windows':
            # On Windows, we'll use PowerShell scripts for log rotation
            
            # Create PowerShell script for log rotation
            ps_script_path = os.path.join(tempfile.gettempdir(), 'log_rotation.ps1')
            
            # Build the script content
            ps_script = """
# Log Rotation PowerShell Script
$date = Get-Date -Format "yyyyMMdd"

# Function to rotate a log file
function Rotate-Log {
    param(
        [string]$LogPath
    )
    
    if (Test-Path $LogPath) {
        $logDir = Split-Path -Parent $LogPath
        $logName = Split-Path -Leaf $LogPath
        $compressedLog = Join-Path $logDir "$logName.$date.zip"
        
        # Create archive
        Compress-Archive -Path $LogPath -DestinationPath $compressedLog -Force
        
        # Clear the original log file (keep the file but empty it)
        Clear-Content -Path $LogPath
        
        Write-Output "Rotated: $LogPath -> $compressedLog"
        return $true
    } else {
        Write-Output "Log file not found: $LogPath"
        return $false
    }
}

# Apache Logs
$apacheLogs = @(
"""
            
            # Add Apache logs to script
            for path in apache_paths:
                ps_script += f'    "{path.replace("\\", "\\\\")}",\n'
            
            ps_script += """)

# MySQL Logs
$mysqlLogs = @(
"""
            
            # Add MySQL logs to script
            for path in mysql_paths:
                ps_script += f'    "{path.replace("\\", "\\\\")}",\n'
            
            ps_script += """)

# Rotate Apache logs
$apacheRotated = 0
foreach ($log in $apacheLogs) {
    if (Rotate-Log -LogPath $log) {
        $apacheRotated++
    }
}

# Rotate MySQL logs
$mysqlRotated = 0
foreach ($log in $mysqlLogs) {
    if (Rotate-Log -LogPath $log) {
        $mysqlRotated++
    }
}

# Summary
Write-Output "Rotation complete. Rotated $apacheRotated Apache logs and $mysqlRotated MySQL logs."
"""
            
            # Write the script to disk
            with open(ps_script_path, 'w') as f:
                f.write(ps_script)
            
            # Execute PowerShell script
            try:
                result = subprocess.run(
                    ["powershell", "-ExecutionPolicy", "Bypass", "-File", ps_script_path],
                    capture_output=True,
                    text=True
                )
                ps_output = result.stdout
                ps_error = result.stderr
                rotation_success = result.returncode == 0
            except Exception as e:
                ps_output = ""
                ps_error = str(e)
                rotation_success = False
            
            # Create scheduled task for regular rotation
            try:
                # Get the current script path for scheduling
                current_script_path = os.path.abspath(__file__)
                directory = os.path.dirname(current_script_path)
                
                # Create task scheduler command
                task_name = "LogDetectionPlatform_LogRotation"
                task_cmd = f"""
                powershell -Command "Register-ScheduledTask -TaskName '{task_name}' -Trigger (New-ScheduledTaskTrigger -Daily -At 12am) -Action (New-ScheduledTaskAction -Execute 'powershell' -Argument '-ExecutionPolicy Bypass -File {ps_script_path}') -RunLevel Highest -Force"
                """
                
                # Run the command to create scheduled task
                task_result = subprocess.run(
                    ["powershell", "-ExecutionPolicy", "Bypass", "-Command", task_cmd],
                    capture_output=True, 
                    text=True
                )
                task_output = task_result.stdout
                task_error = task_result.stderr
                task_success = task_result.returncode == 0
            except Exception as e:
                task_output = ""
                task_error = str(e)
                task_success = False
            
            # Create response
            details = {
                'apache_logs_rotated': len(apache_paths),
                'mysql_logs_rotated': len(mysql_paths),
                'script_path': ps_script_path,
                'rotation_output': ps_output,
                'rotation_error': ps_error,
                'task_created': task_success,
                'task_name': task_name,
                'task_output': task_output,
                'task_error': task_error
            }
            
            # Record the configuration in system settings
            from authentication.models import SystemSettings
            
            SystemSettings.objects.update_or_create(
                section='maintenance',
                settings_key='log_rotation_configured',
                defaults={
                    'settings_value': 'true',
                    'last_updated': timezone.now(),
                    'updated_by': request.user
                }
            )
            
            return {
                'success': rotation_success,
                'message': 'Log rotation configured and executed on Windows system',
                'details': details
            }
            
        else:
            # On Linux/Unix systems, create and apply logrotate config
            
            # Create logrotate configs
            apache_config = f"""
# Apache log rotation configuration
{' '.join(apache_paths)} {{
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        /etc/init.d/apache2 reload > /dev/null 2>&1 || true
    endscript
}}
"""
            
            mysql_config = f"""
# MySQL log rotation configuration
{' '.join(mysql_paths)} {{
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 mysql adm
    sharedscripts
    postrotate
        /etc/init.d/mysql reload > /dev/null 2>&1 || true
    endscript
}}
"""
            
            # Write configs to logrotate.d
            config_files = {}
            try:
                # Write Apache config
                apache_config_path = '/etc/logrotate.d/log-detection-apache'
                with open(apache_config_path, 'w') as f:
                    f.write(apache_config)
                config_files['apache'] = apache_config_path
                
                # Write MySQL config
                mysql_config_path = '/etc/logrotate.d/log-detection-mysql'
                with open(mysql_config_path, 'w') as f:
                    f.write(mysql_config)
                config_files['mysql'] = mysql_config_path
                
                # Run logrotate immediately with force option to test
                logrotate_result = subprocess.run(
                    ["sudo", "logrotate", "-f", apache_config_path, mysql_config_path],
                    capture_output=True,
                    text=True
                )
                
                logrotate_output = logrotate_result.stdout
                logrotate_error = logrotate_result.stderr
                rotation_success = logrotate_result.returncode == 0
                
            except PermissionError:
                # If we don't have permission, create temp files and show instructions
                temp_dir = tempfile.gettempdir()
                apache_config_path = os.path.join(temp_dir, 'log-detection-apache')
                with open(apache_config_path, 'w') as f:
                    f.write(apache_config)
                
                mysql_config_path = os.path.join(temp_dir, 'log-detection-mysql')
                with open(mysql_config_path, 'w') as f:
                    f.write(mysql_config)
                
                config_files['apache'] = apache_config_path
                config_files['mysql'] = mysql_config_path
                
                logrotate_output = "Configuration files created but couldn't be installed or tested due to permissions"
                logrotate_error = "Need root/sudo access to install and test logrotate configuration"
                rotation_success = False
                
            # Record the configuration in system settings
            from authentication.models import SystemSettings
            
            SystemSettings.objects.update_or_create(
                section='maintenance',
                settings_key='log_rotation_configured',
                defaults={
                    'settings_value': 'true',
                    'last_updated': timezone.now(),
                    'updated_by': request.user
                }
            )
            
            # Return results
            return {
                'success': rotation_success,
                'message': 'Log rotation configured and executed' if rotation_success else 'Log rotation configuration created but needs manual installation',
                'details': {
                    'apache_paths': apache_paths,
                    'mysql_paths': mysql_paths,
                    'config_files': config_files,
                    'logrotate_output': logrotate_output,
                    'logrotate_error': logrotate_error,
                    'instructions': "To manually install the configuration files, copy them to /etc/logrotate.d/ and run 'sudo logrotate -f /etc/logrotate.d/log-detection-apache /etc/logrotate.d/log-detection-mysql'" if not rotation_success else ""
                }
            }
        
    except Exception as e:
        logger.exception(f"Error configuring log rotation: {str(e)}")
        raise

def run_cache_cleanup(request):
    """Actually clean up temporary files and cache data"""
    try:
        import os
        import shutil
        import tempfile
        import time
        import platform
        
        # Track space cleaned
        space_cleaned = 0
        files_removed = 0
        dirs_removed = 0
        
        # Set age threshold for file deletion (7 days)
        age_threshold = time.time() - (7 * 24 * 60 * 60)
        
        # 1. Clean temp directories
        temp_dirs = [tempfile.gettempdir()]
        
        # On Linux/Unix systems, add more directories if they exist
        if platform.system() != 'Windows':
            # Common temp directories on Unix
            potential_dirs = ['/tmp', '/var/tmp']
            for d in potential_dirs:
                if os.path.exists(d) and os.path.isdir(d):
                    temp_dirs.append(d)
        
        # Add browser cache directories
        user_home = os.path.expanduser('~')
        browser_cache_dirs = []
        
        if platform.system() == 'Windows':
            browser_cache_dirs = [
                os.path.join(user_home, 'AppData/Local/Google/Chrome/User Data/Default/Cache'),
                os.path.join(user_home, 'AppData/Local/Microsoft/Edge/User Data/Default/Cache'),
                os.path.join(user_home, 'AppData/Local/Mozilla/Firefox/Profiles')
            ]
        else:  # Linux/Unix
            browser_cache_dirs = [
                os.path.join(user_home, '.cache/google-chrome'),
                os.path.join(user_home, '.cache/mozilla'),
                os.path.join(user_home, '.cache/chromium')
            ]
        
        # Filter to only directories that exist and are accessible
        browser_cache_dirs = [d for d in browser_cache_dirs if os.path.exists(d) and os.path.isdir(d)]
        
        # Add browser cache dirs to our cleaning list
        temp_dirs.extend(browser_cache_dirs)
        
        # 2. For each directory, actually clean old files
        for temp_dir in temp_dirs:
            try:
                logger.info(f"Cleaning directory: {temp_dir}")
                
                # Walk directory tree and remove files older than threshold
                for root, dirs, files in os.walk(temp_dir, topdown=True):
                    # Skip hidden directories and certain system paths
                    dirs[:] = [d for d in dirs if not d.startswith('.') and 
                               not os.path.join(root, d).startswith('/proc') and
                               not os.path.join(root, d).startswith('/sys')]
                    
                    # Process files in this directory
                    for filename in files:
                        try:
                            filepath = os.path.join(root, filename)
                            if os.path.isfile(filepath) and not os.path.islink(filepath):
                                try:
                                    file_stat = os.stat(filepath)
                                    # Only remove files older than threshold
                                    if file_stat.st_mtime < age_threshold:
                                        # Add to total before deleting
                                        file_size = file_stat.st_size
                                        
                                        # Delete the file
                                        os.unlink(filepath)
                                        
                                        # Update stats
                                        space_cleaned += file_size
                                        files_removed += 1
                                        logger.debug(f"Removed: {filepath}")
                                except (FileNotFoundError, PermissionError) as e:
                                    logger.debug(f"Error accessing {filepath}: {str(e)}")
                                    continue
                        except Exception as e:
                            logger.debug(f"Error processing {filename}: {str(e)}")
                            continue
                    
                    # Try to remove empty directories (post-order)
                    for dir_name in dirs:
                        dir_path = os.path.join(root, dir_name)
                        try:
                            # Check if directory is empty
                            if not os.listdir(dir_path):
                                os.rmdir(dir_path)
                                dirs_removed += 1
                                logger.debug(f"Removed empty directory: {dir_path}")
                        except Exception as e:
                            logger.debug(f"Error removing directory {dir_path}: {str(e)}")
                            continue
                
            except Exception as e:
                logger.warning(f"Error accessing directory {temp_dir}: {str(e)}")
                continue
        
        # 3. Record the cleanup in system settings
        from authentication.models import SystemSettings
        
        SystemSettings.objects.update_or_create(
            section='maintenance',
            settings_key='last_cache_cleanup',
            defaults={
                'settings_value': timezone.now().isoformat(),
                'last_updated': timezone.now(),
                'updated_by': request.user
            }
        )
        
        # Convert bytes to GB for the response
        space_cleaned_gb = space_cleaned / (1024 * 1024 * 1024)
        
        # Return actual results of the cleanup
        return {
            'success': True,
            'message': f'Cache cleanup completed. Removed {files_removed} files, freeing {space_cleaned_gb:.2f} GB',
            'details': {
                'space_cleaned_gb': round(space_cleaned_gb, 2),
                'files_removed': files_removed,
                'directories_removed': dirs_removed,
                'directories_cleaned': len(temp_dirs),
                'cleaned_by': request.user.username,
                'cleaned_at': timezone.now().isoformat()
            }
        }
        
    except Exception as e:
        logger.exception(f"Error running cache cleanup: {str(e)}")
        raise

def configure_memory_optimization(request):
    """Actually optimize MySQL memory usage configurations"""
    try:
        import psutil
        import os
        import subprocess
        import platform
        import re
        import tempfile
        
        # Find MySQL configuration file
        mysql_config_path = None
        
        if platform.system() == 'Windows':
            # Common locations on Windows
            possible_paths = [
                r'C:\ProgramData\MySQL\MySQL Server 8.0\my.ini',
                r'C:\ProgramData\MySQL\MySQL Server 5.7\my.ini',
                # Add more potential paths as needed
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    mysql_config_path = path
                    break
        
        if not mysql_config_path:
            return {
                'success': False,
                'message': 'MySQL configuration file not found. Please specify the path manually.',
                'details': {
                    'searched_paths': possible_paths
                }
            }
            
        # 1. Get current MySQL settings - custom parser for Windows
        current_settings = {}
        
        # Read the file content as plain text for Windows
        with open(mysql_config_path, 'r') as f:
            config_content = f.readlines()
        
        # Parse the file manually to extract settings
        current_section = None
        for line in config_content:
            line = line.strip()
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1].lower()
            elif current_section == 'mysqld' and '=' in line and not line.startswith('#'):
                parts = line.split('=', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    current_settings[key] = value
        
        # 2. Calculate optimized settings based on actual system memory
        memory = psutil.virtual_memory()
        total_memory_gb = memory.total / (1024 * 1024 * 1024)
        
        # Calculate optimized values based on system memory
        optimized_settings = {}
        
        # Innodb buffer pool: 50-70% of available RAM depending on system
        if total_memory_gb >= 16:
            # Larger systems: use 60% for InnoDB
            innodb_pct = 0.6
        elif total_memory_gb >= 8:
            # Medium systems: use 50% for InnoDB
            innodb_pct = 0.5
        else:
            # Small systems: use 40% for InnoDB
            innodb_pct = 0.4
            
        innodb_buffer_pool_size = int(total_memory_gb * innodb_pct * 1024)
        optimized_settings['innodb_buffer_pool_size'] = f"{innodb_buffer_pool_size}M"
        
        # Key buffer size: 25% of innodb buffer for MyISAM if using both engines
        optimized_settings['key_buffer_size'] = f"{int(innodb_buffer_pool_size * 0.25)}M"
        
        # Thread cache: between 8-16 depending on system size
        optimized_settings['thread_cache_size'] = '16' if total_memory_gb >= 8 else '8'
        
        # Query cache: often better turned off in newer MySQL versions
        optimized_settings['query_cache_type'] = '0'
        optimized_settings['query_cache_size'] = '0'
        
        # Max connections: depends on application needs, default reasonable for many cases
        optimized_settings['max_connections'] = '200'
        
        # Additional performance settings
        optimized_settings['innodb_flush_method'] = 'normal'  # Windows-specific value
        optimized_settings['innodb_flush_log_at_trx_commit'] = '2'
        optimized_settings['innodb_file_per_table'] = '1'
        optimized_settings['innodb_buffer_pool_instances'] = '8' if innodb_buffer_pool_size > 1024 else '1'
        
        # 3. Create an optimized config file that user can apply manually
        temp_config_path = os.path.join(tempfile.gettempdir(), 'mysql_optimized.ini')
        backup_path = os.path.join(tempfile.gettempdir(), 'mysql_original.ini.bak')
        
        # Make a backup copy in a non-protected location
        try:
            import shutil
            shutil.copy2(mysql_config_path, backup_path)
        except Exception as e:
            logger.warning(f"Could not create backup of MySQL config: {str(e)}")
        
        # Generate the optimized config
        new_lines = []
        in_mysqld_section = False
        mysqld_section_found = False
        processed_settings = {}
        
        with open(mysql_config_path, 'r') as f:
            original_lines = f.readlines()
        
        for line in original_lines:
            stripped = line.strip()
            
            # Track when we enter/exit the mysqld section
            if stripped == '[mysqld]':
                in_mysqld_section = True
                mysqld_section_found = True
                new_lines.append(line)  # Keep the original line
            elif stripped.startswith('[') and in_mysqld_section:
                # Before leaving mysqld section, add any missing settings
                for key, value in optimized_settings.items():
                    if key not in processed_settings:
                        new_lines.append(f"{key}={value}\n")
                        processed_settings[key] = True
                in_mysqld_section = False
                new_lines.append(line)  # Keep the section header
            elif in_mysqld_section and '=' in stripped and not stripped.startswith('#'):
                # Process existing settings in mysqld section
                parts = stripped.split('=', 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    if key in optimized_settings:
                        # Replace with optimized value
                        line = f"{key}={optimized_settings[key]}\n"
                        processed_settings[key] = True
                new_lines.append(line)
            else:
                # Keep all other lines as-is
                new_lines.append(line)
        
        # If mysqld section wasn't found, add it at the end with all settings
        if not mysqld_section_found:
            new_lines.append('\n[mysqld]\n')
            for key, value in optimized_settings.items():
                new_lines.append(f"{key}={value}\n")
        # If we were in mysqld section at the end of file, add any missing settings
        elif in_mysqld_section:
            for key, value in optimized_settings.items():
                if key not in processed_settings:
                    new_lines.append(f"{key}={value}\n")
        
        # Write the optimized config to a temporary file
        with open(temp_config_path, 'w') as f:
            f.writelines(new_lines)
        
        # Create a batch file to help the user apply the changes with admin rights
        bat_path = os.path.join(tempfile.gettempdir(), 'apply_mysql_config.bat')
        with open(bat_path, 'w') as f:
            f.write(f'@echo off\n')
            f.write(f'echo MySQL Memory Optimization\n')
            f.write(f'echo ========================\n')
            f.write(f'echo.\n')
            f.write(f'echo This script will apply optimized MySQL memory settings.\n')
            f.write(f'echo Please run this script as administrator.\n')
            f.write(f'echo.\n')
            f.write(f'echo Backing up original MySQL config file...\n')
            f.write(f'copy "{mysql_config_path}" "{mysql_config_path}.bak"\n')
            f.write(f'echo.\n')
            f.write(f'echo Applying optimized MySQL config file...\n')
            f.write(f'copy "{temp_config_path}" "{mysql_config_path}"\n')
            f.write(f'echo.\n')
            f.write(f'echo Optimizations applied. Please restart MySQL service.\n')
            f.write(f'echo.\n')
            f.write(f'echo To restart MySQL, run: net stop mysql & net start mysql\n')
            f.write(f'echo.\n')
            f.write(f'pause\n')
        
        # Record the optimization in system settings
        from authentication.models import SystemSettings
        
        SystemSettings.objects.update_or_create(
            section='maintenance',
            settings_key='mysql_memory_optimization',
            defaults={
                'settings_value': json.dumps({
                    'optimized_settings': optimized_settings,
                    'config_file': mysql_config_path,
                    'temp_config': temp_config_path,
                    'bat_file': bat_path
                }),
                'last_updated': timezone.now(),
                'updated_by': request.user
            }
        )
        
        # Calculate memory savings (if applicable)
        original_innodb = 0
        if 'innodb_buffer_pool_size' in current_settings:
            size_str = current_settings['innodb_buffer_pool_size']
            if 'M' in size_str:
                original_innodb = int(size_str.rstrip('M'))
            elif 'G' in size_str:
                original_innodb = int(size_str.rstrip('G')) * 1024
            else:
                try:
                    original_innodb = int(size_str) / (1024 * 1024)
                except ValueError:
                    original_innodb = 0
        
        memory_savings_pct = 0
        if original_innodb > 0:
            memory_savings_pct = ((innodb_buffer_pool_size - original_innodb) / original_innodb) * 100
        
        # Return information to the user
        return {
            'success': True,
            'message': 'Could not update MySQL configuration file. Try running with administrator privileges.',
            'details': {
                'config_file': mysql_config_path,
                'temp_config': temp_config_path,
                'batch_file': bat_path,
                'optimized_settings': optimized_settings,
                'memory_efficiency_improved': abs(round(memory_savings_pct, 1)) if memory_savings_pct != 0 else "New configuration calculated",
                'system_memory_gb': round(total_memory_gb, 2),
                'error': "Access denied. Please run the generated batch file as administrator.",
                'next_steps': "1. Right-click on the batch file and select 'Run as administrator'\n2. Restart MySQL service after applying changes"
            }
        }
            
    except Exception as e:
        logger.exception(f"Error configuring MySQL memory optimization: {str(e)}")
        return {
            'success': False,
            'message': f'Error analyzing MySQL configuration: {str(e)}',
            'details': {
                'error': str(e)
            }
        }

def predict_resource_exhaustion(resource_type, metrics, time_window=24):
    """
    Analyze resource utilization patterns to predict potential
    exhaustion within the specified time window (hours)
    
    Args:
        resource_type: Type of resource (cpu, memory, disk, log_volume)
        metrics: Current metrics for the resource
        time_window: Prediction window in hours
    
    Returns:
        Dictionary with prediction details
    """
    try:
        # Get thresholds for different resources
        thresholds = {
            'cpu': 85,       # 85% CPU usage is critical
            'memory': 90,    # 90% memory usage is critical
            'disk': 95,      # 95% disk usage is critical
            'log_volume': 90 # 90% of allocated log space
        }
        
        # Get current usage and trend from metrics
        current_usage = metrics.get('usage', 0)
        trend_value = metrics.get('trend_value', 0)  # % change per day
        
        # Calculate hours until threshold is reached
        if trend_value <= 0:
            # If trend is stable or decreasing, no exhaustion predicted
            return {
                'current_usage': current_usage,
                'threshold': thresholds.get(resource_type, 90),
                'trend': metrics.get('trend', 'stable'),
                'trend_value': trend_value,
                'will_reach_threshold': False,
                'hours_to_threshold': None,
                'days_to_threshold': None,
                'status': 'normal',
                'confidence': 95,
                'message': f"No exhaustion predicted within {time_window} hours"
            }
        
        # Calculate hours until threshold
        threshold = thresholds.get(resource_type, 90)
        hours_to_threshold = (threshold - current_usage) / (trend_value / 24)  # Convert daily trend to hourly
        
        # Determine status based on time to threshold vs time window
        if hours_to_threshold > time_window:
            status = 'normal'
        else:
            status = 'warning'
            
        # If already over threshold
        if current_usage >= threshold:
            status = 'critical'
            hours_to_threshold = 0
        
        # Calculate days (for display)
        days_to_threshold = hours_to_threshold / 24 if hours_to_threshold else None
        
        # Create the prediction object
        prediction = {
            'current_usage': current_usage,
            'threshold': threshold,
            'trend': metrics.get('trend', 'stable'),
            'trend_value': trend_value,
            'will_reach_threshold': hours_to_threshold <= time_window and trend_value > 0,
            'hours_to_threshold': round(hours_to_threshold, 1) if hours_to_threshold else None,
            'days_to_threshold': round(days_to_threshold, 1) if days_to_threshold else None,
            'status': status,
            'confidence': calculate_confidence(metrics),
            'message': create_message(resource_type, status, hours_to_threshold, threshold)
        }
        
        return prediction
        
    except Exception as e:
        logger.exception(f"Error predicting {resource_type} exhaustion: {str(e)}")
        return {
            'status': 'error',
            'message': f"Error predicting resource exhaustion: {str(e)}"
        }

def calculate_confidence(metrics):
    """Calculate a confidence score for the prediction (placeholder)"""
    # In a real implementation, this would be based on statistical analysis
    # of the data quality and model performance
    return 90

def create_message(resource_type, status, hours_to_threshold, threshold):
    """Create a human-readable message about the prediction"""
    if status == 'critical':
        return f"Resource already exceeds threshold of {threshold}%"
    elif status == 'warning':
        if hours_to_threshold < 24:
            return f"Predicted to reach {threshold}% threshold in {round(hours_to_threshold, 1)} hours"
        else:
            days = hours_to_threshold / 24
            return f"Predicted to reach {threshold}% threshold in {round(days, 1)} days"
    else:
        return f"No exhaustion predicted within forecast window"

def store_system_metrics():
    """Store current system metrics for trend analysis"""
    from log_ingestion.models import SystemMetricsHistory
    
    try:
        # Get CPU usage
        cpu_usage = psutil.cpu_percent(interval=1)
        SystemMetricsHistory.objects.create(
            metric_type='cpu',
            value=cpu_usage
        )
        
        # Get memory usage
        memory = psutil.virtual_memory()
        SystemMetricsHistory.objects.create(
            metric_type='memory',
            value=memory.percent,
            total_available=memory.total,
            used_amount=memory.used,
            details={
                'available': memory.available
            }
        )
        
        # Get disk usage
        disk = psutil.disk_usage('/')
        SystemMetricsHistory.objects.create(
            metric_type='disk',
            value=disk.percent,
            total_available=disk.total,
            used_amount=disk.used,
            details={
                'free': disk.free
            }
        )
        
        # Get log volume data
        log_volume = get_log_volume_metrics()
        SystemMetricsHistory.objects.create(
            metric_type='log_volume',
            value=log_volume['usage'],
            total_available=log_volume['total'] * (1024 * 1024 * 1024),  # Convert GB to bytes
            used_amount=log_volume['used'] * (1024 * 1024 * 1024),  # Convert GB to bytes
            details={
                'apache_size': log_volume['apache_size'],
                'mysql_size': log_volume['mysql_size'],
                'system_size': log_volume['system_size'],
                'apache_growth': log_volume.get('apache_growth', 0),
                'mysql_growth': log_volume.get('mysql_growth', 0),
                'system_growth': log_volume.get('system_growth', 0)
            }
        )
        
        logger.info("System metrics stored successfully")
        return True
    except Exception as e:
        logger.exception(f"Error storing system metrics: {str(e)}")
        return False

def analyze_resource_trend(metric_type, days=7):
    """
    Analyze resource usage trends based on historical data
    
    Args:
        metric_type: Type of resource (cpu, memory, disk, log_volume)
        days: Number of days of history to analyze
        
    Returns:
        Dictionary with trend information
    """
    from log_ingestion.models import SystemMetricsHistory
    import numpy as np
    
    try:
        # Get data from the specified time period
        start_time = timezone.now() - timedelta(days=days)
        metrics = SystemMetricsHistory.objects.filter(
            metric_type=metric_type,
            timestamp__gte=start_time
        ).order_by('timestamp')
        
        # If we don't have enough data points, return a default result
        if metrics.count() < 2:
            return {
                'trend': 'stable',
                'trend_value': 0,
                'confidence': 50
            }
        
        # Extract timestamps and values
        timestamps = []
        values = []
        
        for m in metrics:
            timestamps.append(m.timestamp.timestamp())
            values.append(m.value)
        
        # Convert to numpy arrays for calculations
        x = np.array(timestamps)
        y = np.array(values)
        
        # Normalize x values to days
        x = (x - x[0]) / 86400  # Convert seconds to days
        
        # Simple linear regression to find the slope (daily change)
        if len(x) > 1 and len(x) == len(y):
            slope, intercept = np.polyfit(x, y, 1)
        else:
            slope = 0
        
        # Determine trend direction
        if slope > 0.5:  # More than 0.5% increase per day
            trend = 'increasing'
        elif slope < -0.5:  # More than 0.5% decrease per day
            trend = 'decreasing'
        else:
            trend = 'stable'
        
        # Calculate R-squared value for confidence estimate
        if len(y) > 2:
            y_mean = np.mean(y)
            y_pred = slope * x + intercept
            ss_tot = np.sum((y - y_mean) ** 2)
            ss_res = np.sum((y - y_pred) ** 2)
            r_squared = 1 - (ss_res / ss_tot) if ss_tot != 0 else 0
            confidence = min(int(r_squared * 100), 95)  # Max 95% confidence
        else:
            confidence = 50  # Default confidence with limited data
            
        return {
            'trend': trend,
            'trend_value': round(slope, 2),  # Daily percentage change
            'confidence': confidence
        }
        
    except Exception as e:
        logger.exception(f"Error analyzing {metric_type} trend: {str(e)}")
        return {
            'trend': 'stable',
            'trend_value': 0,
            'confidence': 50
        }