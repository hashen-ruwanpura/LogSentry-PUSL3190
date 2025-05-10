import logging
import json
import psutil
import time
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
        
        # Get system logs size (common locations)
        system_size = 0
        system_log_paths = ['/var/log', 'C:\\Windows\\Logs']
        
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