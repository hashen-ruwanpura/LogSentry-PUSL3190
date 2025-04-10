from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.db.models import Count, Q
from django.views.decorators.csrf import ensure_csrf_cookie
from django.template.exceptions import TemplateDoesNotExist
import json
import csv
from datetime import timedelta, datetime
from io import StringIO
import logging

from .models import LogReport

logger = logging.getLogger(__name__)

def is_admin(user):
    """Helper function to check if user is admin"""
    return user.is_authenticated and user.is_superuser

@login_required
@user_passes_test(is_admin, login_url='/login/')
@ensure_csrf_cookie
def admin_reports_view(request):
    """Admin reports dashboard view"""
    try:
        return render(request, 'frontend/admin/adminreports.html')
    except TemplateDoesNotExist:
        return render(request, 'admin/adminreports.html')

@login_required
@user_passes_test(is_admin)
def dashboard_data(request):
    """API endpoint to get dashboard data"""
    print("dashboard_data function called")
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        print(f"Request data: {data}")
        
        start_date = datetime.strptime(data.get('startDate'), '%Y-%m-%d').date()
        end_date = datetime.strptime(data.get('endDate'), '%Y-%m-%d').date()
        log_type = data.get('logType', 'all')
        severity = data.get('severity', 'all')
        group_by = data.get('groupBy', 'day')
        
        print(f"Parsed dates: {start_date} to {end_date}, type: {log_type}, severity: {severity}")
        
        # End date is inclusive
        end_date = datetime.combine(end_date, datetime.max.time())
        
        # Base query filters
        base_filters = Q(timestamp__gte=start_date, timestamp__lte=end_date)
        
        if log_type != 'all':
            base_filters &= Q(log_type=log_type)
            
        if severity != 'all':
            base_filters &= Q(severity=severity)
            
        # Check if we have any reports
        total_count = LogReport.objects.count()
        filtered_count = LogReport.objects.filter(base_filters).count()
        print(f"Total reports: {total_count}, Filtered reports: {filtered_count}")
        
        # Get previous period dates for comparison
        delta_days = (end_date.date() - start_date).days + 1
        prev_end_date = start_date - timedelta(days=1)
        prev_start_date = prev_end_date - timedelta(days=delta_days-1)
        
        # Calculate statistics
        current_stats = calculate_stats(base_filters)
        prev_filters = Q(timestamp__gte=prev_start_date, timestamp__lte=prev_end_date)
        if log_type != 'all':
            prev_filters &= Q(log_type=log_type)
        prev_stats = calculate_stats(prev_filters)
        
        # Calculate percentage changes
        stats = {
            'totalThreats': current_stats['total_threats'],
            'intrusionAttempts': current_stats['intrusion_attempts'],
            'systemErrors': current_stats['system_errors'],
            'blockedAttacks': current_stats['blocked_attacks'],
            'threatChange': calculate_percentage_change(current_stats['total_threats'], prev_stats['total_threats']),
            'intrusionChange': calculate_percentage_change(current_stats['intrusion_attempts'], prev_stats['intrusion_attempts']),
            'errorChange': calculate_percentage_change(current_stats['system_errors'], prev_stats['system_errors']),
            'blockedChange': calculate_percentage_change(current_stats['blocked_attacks'], prev_stats['blocked_attacks'])
        }
        
        # Get severity distribution
        severity_dist = get_severity_distribution(base_filters)
        
        # Get threat trend data
        threat_trend = get_threat_trend(base_filters, start_date, end_date, group_by)
        
        # Get attack types
        attack_types = get_attack_types(base_filters)
        
        # Get recent threats
        recent_threats = get_recent_threats(base_filters)
        
        response_data = {
            'stats': stats,
            'severity': severity_dist,
            'threatTrend': threat_trend,
            'attackTypes': attack_types,
            'attackSources': [],  # Empty since we removed this section
            'recentThreats': recent_threats
        }
        
        return JsonResponse(response_data)
    except Exception as e:
        import traceback
        print(f"Error in dashboard_data: {str(e)}")
        print(traceback.format_exc())
        logger.error(f"Error in dashboard_data: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_admin)
def simple_dashboard_data(request):
    """Dashboard data endpoint that properly displays database data with filtering"""
    print("simple_dashboard_data function called")
    
    try:
        # Print request details
        print(f"Method: {request.method}")
        if request.method == 'POST':
            print(f"Request body: {request.body.decode('utf-8')}")
            
        # Default filter values - Use current date for better results
        end_date = timezone.now()
        start_date = end_date - timedelta(days=30)
        log_type = 'all'
        severity = 'all'
        group_by = 'day'
        
        # Get filters from request if it's a POST
        if request.method == 'POST':
            try:
                data = json.loads(request.body)
                print(f"Received filter data: {data}")
                
                if 'startDate' in data and data['startDate']:
                    try:
                        start_date = datetime.strptime(data.get('startDate'), '%Y-%m-%d')
                    except ValueError as e:
                        print(f"Invalid startDate format: {e}")
                
                if 'endDate' in data and data['endDate']:
                    try:
                        # Make end date inclusive
                        end_date = datetime.strptime(data.get('endDate'), '%Y-%m-%d')
                        end_date = datetime.combine(end_date, datetime.max.time())
                    except ValueError as e:
                        print(f"Invalid endDate format: {e}")
                
                if 'logType' in data:
                    log_type = data.get('logType')
                
                if 'severity' in data:
                    severity = data.get('severity')
                
                if 'groupBy' in data:
                    group_by = data.get('groupBy')
                
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")
        
        # Print the actual filters being used
        print(f"Using filters: {start_date} to {end_date}, type: {log_type}, severity: {severity}, groupBy: {group_by}")
        
        # Build filter query
        filters = Q(timestamp__gte=start_date, timestamp__lte=end_date)
        if log_type != 'all':
            filters &= Q(log_type=log_type)
        if severity != 'all':
            filters &= Q(severity=severity)
            
        # Get filtered data
        filtered_reports = LogReport.objects.filter(filters)
        
        # Count statistics
        total_count = filtered_reports.count()
        high_count = filtered_reports.filter(severity='high').count()
        medium_count = filtered_reports.filter(severity='medium').count()
        low_count = filtered_reports.filter(severity='low').count()
        
        # Count threats by type
        threat_types = {}
        for threat in filtered_reports.values('threat_type').annotate(count=Count('id')).order_by('-count')[:10]:
            threat_types[threat['threat_type']] = threat['count']
        
        # Get previous period data for comparison
        delta_days = (end_date.date() - start_date.date()).days
        prev_end_date = start_date - timedelta(microseconds=1)
        prev_start_date = prev_end_date - timedelta(days=delta_days)
        prev_filters = Q(timestamp__gte=prev_start_date, timestamp__lte=prev_end_date)
        if log_type != 'all':
            prev_filters &= Q(log_type=log_type)
        if severity != 'all':
            prev_filters &= Q(severity=severity)
        prev_count = LogReport.objects.filter(prev_filters).count()
        
        # Calculate percentage changes
        threat_change = calculate_percentage_change(total_count, prev_count)
        
        # Count intrusion attempts
        intrusion_attempts = filtered_reports.filter(
            Q(threat_type__icontains='injection') | 
            Q(threat_type__icontains='brute force') |
            Q(threat_type__icontains='suspicious')
        ).count()
        prev_intrusion = LogReport.objects.filter(
            prev_filters & (
                Q(threat_type__icontains='injection') | 
                Q(threat_type__icontains='brute force') |
                Q(threat_type__icontains='suspicious')
            )
        ).count()
        intrusion_change = calculate_percentage_change(intrusion_attempts, prev_intrusion)
        
        # Count system errors
        system_errors = filtered_reports.filter(
            Q(status_code__gte=500) | 
            Q(threat_type__icontains='error')
        ).count()
        prev_errors = LogReport.objects.filter(
            prev_filters & (
                Q(status_code__gte=500) | 
                Q(threat_type__icontains='error')
            )
        ).count()
        error_change = calculate_percentage_change(system_errors, prev_errors)
        
        # Count blocked attacks
        blocked_attacks = filtered_reports.filter(status='resolved').count()
        prev_blocked = LogReport.objects.filter(prev_filters & Q(status='resolved')).count()
        blocked_change = calculate_percentage_change(blocked_attacks, prev_blocked)
        
        # Generate trend data
        trend_data = generate_threat_trend_data(start_date, end_date, filters, group_by)
        
        # Create response data
        response_data = {
            'stats': {
                'totalThreats': total_count,
                'intrusionAttempts': intrusion_attempts,
                'systemErrors': system_errors,
                'blockedAttacks': blocked_attacks,
                'threatChange': threat_change,
                'intrusionChange': intrusion_change,
                'errorChange': error_change,
                'blockedChange': blocked_change
            },
            'severity': {
                'high': high_count,
                'medium': medium_count,
                'low': low_count
            },
            'threatTrend': trend_data,
            'attackTypes': threat_types,
            'recentThreats': []
        }
        
        # Get recent threats
        for threat in filtered_reports.order_by('-timestamp')[:10]:
            # Correctly handle the choices display without using get_display
            severity_display = dict(LogReport.SEVERITY_CHOICES).get(threat.severity, threat.severity)
            status_display = dict(LogReport.STATUS_CHOICES).get(threat.status, threat.status)
            log_type_display = dict(LogReport.LOG_TYPE_CHOICES).get(threat.log_type, threat.log_type)
            
            response_data['recentThreats'].append({
                'id': threat.id,
                'timestamp': threat.timestamp.isoformat(),
                'sourceIp': str(threat.source_ip),
                'logType': log_type_display,
                'threatType': threat.threat_type,
                'severity': severity_display.capitalize(),
                'status': status_display.capitalize()
            })
        
        return JsonResponse(response_data)
    except Exception as e:
        import traceback
        print(f"Error in simple_dashboard_data: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({
            'error': str(e)
        }, status=500)

def generate_threat_trend_data(start_date, end_date, filters, group_by='day'):
    """Generate threat trend data for the specified period and grouping"""
    # Define date formats for display and database extraction
    date_formats = {
        'day': '%Y-%m-%d',
        'week': '%Y-%U',
        'month': '%Y-%m'
    }
    
    # Generate date labels based on grouping
    date_labels = []
    high_data = []
    medium_data = []
    low_data = []
    
    # Generate appropriate date ranges based on grouping
    if group_by == 'day':
        # Daily grouping
        current_date = start_date.date()
        while current_date <= end_date.date():
            date_labels.append(current_date.strftime(date_formats[group_by]))
            
            # Filter data for this day
            day_start = datetime.combine(current_date, datetime.min.time())
            day_end = datetime.combine(current_date, datetime.max.time())
            day_filter = filters & Q(timestamp__gte=day_start, timestamp__lte=day_end)
            
            # Count by severity
            high_data.append(LogReport.objects.filter(day_filter & Q(severity='high')).count())
            medium_data.append(LogReport.objects.filter(day_filter & Q(severity='medium')).count())
            low_data.append(LogReport.objects.filter(day_filter & Q(severity='low')).count())
            
            current_date += timedelta(days=1)
    
    elif group_by == 'week':
        # Weekly grouping
        current_date = start_date.date()
        # Move to start of week (Monday)
        current_date -= timedelta(days=current_date.weekday())
        
        while current_date <= end_date.date():
            week_label = current_date.strftime(date_formats[group_by])
            date_labels.append(week_label)
            
            # Filter data for this week
            week_start = datetime.combine(current_date, datetime.min.time())
            week_end = datetime.combine(current_date + timedelta(days=6), datetime.max.time())
            week_filter = filters & Q(timestamp__gte=week_start, timestamp__lte=week_end)
            
            # Count by severity
            high_data.append(LogReport.objects.filter(week_filter & Q(severity='high')).count())
            medium_data.append(LogReport.objects.filter(week_filter & Q(severity='medium')).count())
            low_data.append(LogReport.objects.filter(week_filter & Q(severity='low')).count())
            
            current_date += timedelta(days=7)
    
    elif group_by == 'month':
        # Monthly grouping
        current_date = datetime(start_date.year, start_date.month, 1).date()
        
        while current_date <= end_date.date():
            month_label = current_date.strftime(date_formats[group_by])
            date_labels.append(month_label)
            
            # Get next month
            if current_date.month == 12:
                next_month = datetime(current_date.year + 1, 1, 1).date()
            else:
                next_month = datetime(current_date.year, current_date.month + 1, 1).date()
            
            # Filter data for this month
            month_start = datetime.combine(current_date, datetime.min.time())
            month_end = datetime.combine(next_month - timedelta(days=1), datetime.max.time())
            month_filter = filters & Q(timestamp__gte=month_start, timestamp__lte=month_end)
            
            # Count by severity
            high_data.append(LogReport.objects.filter(month_filter & Q(severity='high')).count())
            medium_data.append(LogReport.objects.filter(month_filter & Q(severity='medium')).count())
            low_data.append(LogReport.objects.filter(month_filter & Q(severity='low')).count())
            
            current_date = next_month
    
    return {
        'labels': date_labels,
        'high': high_data,
        'medium': medium_data,
        'low': low_data
    }

@login_required
@user_passes_test(is_admin)
def threat_trend_data(request):
    """API endpoint to get threat trend data"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        start_date = datetime.strptime(data.get('startDate'), '%Y-%m-%d').date()
        end_date = datetime.strptime(data.get('endDate'), '%Y-%m-%d').date()
        log_type = data.get('logType', 'all')
        severity = data.get('severity', 'all')
        group_by = data.get('groupBy', 'day')
        
        # End date is inclusive
        end_date = datetime.combine(end_date, datetime.max.time())
        
        # Base query filters
        base_filters = Q(timestamp__gte=start_date, timestamp__lte=end_date)
        
        if log_type != 'all':
            base_filters &= Q(log_type=log_type)
            
        if severity != 'all':
            base_filters &= Q(severity=severity)
        
        # Get threat trend data
        threat_trend = get_threat_trend(base_filters, start_date, end_date, group_by)
        
        return JsonResponse(threat_trend)
    except Exception as e:
        logger.error(f"Error in threat_trend_data: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_admin)
def threat_detail(request, threat_id):
    """API endpoint to get threat details"""
    try:
        threat = get_object_or_404(LogReport, pk=threat_id)
        
        # Format the data for frontend
        data = {
            'id': threat.id,
            'timestamp': threat.timestamp.isoformat(),
            'sourceIp': threat.source_ip,
            'country': f"{threat.country_name} ({threat.country_code})" if threat.country_name else "Unknown",
            'logType': threat.get_log_type_display(),
            'threatType': threat.threat_type,
            'severity': threat.get_severity_display(),
            'status': threat.get_status_display(),
            'rawLog': threat.raw_log,
            'notes': threat.notes,
            
            # Apache specific fields
            'requestMethod': threat.request_method,
            'requestPath': threat.request_path,
            'statusCode': threat.status_code,
            'responseSize': threat.response_size,
            'userAgent': threat.user_agent,
            
            # MySQL specific fields
            'database': threat.database,
            'queryType': threat.query_type
        }
        
        return JsonResponse(data)
    except Exception as e:
        logger.error(f"Error in threat_detail: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_admin)
def resolve_threat(request, threat_id):
    """API endpoint to mark a threat as resolved"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        threat = get_object_or_404(LogReport, pk=threat_id)
        threat.status = 'resolved'
        threat.resolved_by = request.user
        threat.resolved_at = timezone.now()
        threat.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Threat marked as resolved successfully.'
        })
    except Exception as e:
        logger.error(f"Error in resolve_threat: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_admin)
def export_reports(request):
    """API endpoint to export reports in different formats"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        # Handle both form data and JSON input
        if 'application/json' in request.content_type:
            data = json.loads(request.body)
            start_date = datetime.strptime(data.get('startDate'), '%Y-%m-%d').date()
            end_date = datetime.strptime(data.get('endDate'), '%Y-%m-%d').date()
            log_type = data.get('logType', 'all')
            severity = data.get('severity', 'all')
            export_format = data.get('format', 'csv')
        else:
            start_date = datetime.strptime(request.POST.get('startDate'), '%Y-%m-%d').date()
            end_date = datetime.strptime(request.POST.get('endDate'), '%Y-%m-%d').date()
            log_type = request.POST.get('logType', 'all')
            severity = request.POST.get('severity', 'all')
            export_format = request.POST.get('format', 'csv')
        
        # Print debug information
        print(f"Exporting reports: {start_date} to {end_date}, type: {log_type}, severity: {severity}, format: {export_format}")
        
        # End date is inclusive
        end_date = datetime.combine(end_date, datetime.max.time())
        
        # Base query filters
        base_filters = Q(timestamp__gte=start_date, timestamp__lte=end_date)
        
        if log_type != 'all':
            base_filters &= Q(log_type=log_type)
            
        if severity != 'all':
            base_filters &= Q(severity=severity)
        
        # Get data
        reports = LogReport.objects.filter(base_filters).order_by('-timestamp')
        
        if export_format == 'csv':
            return export_csv(reports)
        elif export_format == 'json':
            return export_json(reports)
        elif export_format == 'pdf':
            return export_pdf(reports, start_date, end_date)
        else:
            return JsonResponse({'error': 'Invalid export format'}, status=400)
    except Exception as e:
        import traceback
        error_msg = str(e)
        tb = traceback.format_exc()
        logger.error(f"Error in export_reports: {error_msg}\n{tb}")
        return JsonResponse({'error': error_msg}, status=500)

# Helper functions
def calculate_stats(filters):
    """Calculate statistics based on filters"""
    # Total threats
    total_threats = LogReport.objects.filter(filters).count()
    
    # Intrusion attempts (SQL injection, XSS, etc.)
    intrusion_attempts = LogReport.objects.filter(
        filters & (
            Q(threat_type__icontains='sql injection') |
            Q(threat_type__icontains='xss') |
            Q(threat_type__icontains='csrf') |
            Q(threat_type__icontains='remote code') |
            Q(threat_type__icontains='command injection')
        )
    ).count()
    
    # System errors (500 errors, database errors)
    system_errors = LogReport.objects.filter(
        filters & (
            Q(status_code__gte=500) |
            Q(threat_type__icontains='error') |
            Q(threat_type__icontains='exception')
        )
    ).count()
    
    # Blocked attacks
    blocked_attacks = LogReport.objects.filter(
        filters & Q(status='resolved')
    ).count()
    
    return {
        'total_threats': total_threats,
        'intrusion_attempts': intrusion_attempts,
        'system_errors': system_errors,
        'blocked_attacks': blocked_attacks
    }

def calculate_percentage_change(current, previous):
    """Calculate percentage change between two values"""
    if previous == 0:
        # If previous value is 0, we can't calculate percentage change
        # Return 0 if current is also 0, else return 100% increase
        return 0 if current == 0 else 100
    
    change = ((current - previous) / previous) * 100
    return round(change)

def get_severity_distribution(filters):
    """Get severity distribution"""
    severity_counts = LogReport.objects.filter(filters).values('severity').annotate(count=Count('id'))
    
    # Initialize with zeros
    high = medium = low = 0
    
    for item in severity_counts:
        if item['severity'] == 'high':
            high = item['count']
        elif item['severity'] == 'medium':
            medium = item['count']
        elif item['severity'] == 'low':
            low = item['count']
    
    return {
        'high': high,
        'medium': medium,
        'low': low
    }

def get_threat_trend(filters, start_date, end_date, group_by):
    """Get threat trend data for the given period and grouping"""
    # Define date formats for display
    date_formats = {
        'day': '%Y-%m-%d',
        'week': '%Y-%U',
        'month': '%Y-%m'
    }
    
    # Initialize empty dictionaries to store counts
    high_counts = {}
    medium_counts = {}
    low_counts = {}
    
    # Generate all dates/periods in the range for display
    date_labels = []
    current_date = start_date
    
    # Generate date range labels based on grouping
    while current_date <= end_date.date():
        date_str = current_date.strftime(date_formats[group_by])
        if date_str not in date_labels:
            date_labels.append(date_str)
            high_counts[date_str] = 0
            medium_counts[date_str] = 0
            low_counts[date_str] = 0
        
        # Increment date based on grouping
        if group_by == 'day':
            current_date += timedelta(days=1)
        elif group_by == 'week':
            current_date += timedelta(days=7)
        elif group_by == 'month':
            if current_date.month == 12:
                current_date = current_date.replace(year=current_date.year + 1, month=1)
            else:
                next_month = current_date.month + 1
                current_date = current_date.replace(month=next_month)
    
    # Get all reports in the date range matching the filters
    reports = LogReport.objects.filter(filters)
    
    # Count reports for each severity and date
    for report in reports:
        # Format the date based on grouping
        if group_by == 'day':
            date_str = report.timestamp.strftime('%Y-%m-%d')
        elif group_by == 'week':
            date_str = report.timestamp.strftime('%Y-%U')
        elif group_by == 'month':
            date_str = report.timestamp.strftime('%Y-%m')
        
        # Skip if date is not in our range (shouldn't happen, but just in case)
        if date_str not in date_labels:
            continue
        
        # Count by severity
        if report.severity == 'high':
            high_counts[date_str] += 1
        elif report.severity == 'medium':
            medium_counts[date_str] += 1
        elif report.severity == 'low':
            low_counts[date_str] += 1
    
    # Convert dictionaries to lists in the same order as date_labels
    high_data = [high_counts.get(date, 0) for date in date_labels]
    medium_data = [medium_counts.get(date, 0) for date in date_labels]
    low_data = [low_counts.get(date, 0) for date in date_labels]
    
    return {
        'labels': date_labels,
        'high': high_data,
        'medium': medium_data,
        'low': low_data
    }

def get_attack_types(filters):
    """Get top attack types"""
    attack_types = LogReport.objects.filter(filters)\
        .values('threat_type')\
        .annotate(count=Count('id'))\
        .order_by('-count')[:10]
    
    # Format for frontend
    result = {}
    for item in attack_types:
        result[item['threat_type']] = item['count']
    
    return result

def get_attack_sources(filters):
    """Get attack sources by country"""
    sources = LogReport.objects.filter(filters)\
        .exclude(country_code__isnull=True)\
        .values('country_code')\
        .annotate(count=Count('id'))\
        .order_by('-count')[:20]
    
    # Format for frontend
    result = []
    for item in sources:
        result.append({
            'countryCode': item['country_code'],
            'count': item['count']
        })
    
    return result

def get_recent_threats(filters):
    """Get recent threats for the table"""
    threats = LogReport.objects.filter(filters).order_by('-timestamp')[:10]
    
    # Format for frontend
    result = []
    for threat in threats:
        result.append({
            'id': threat.id,
            'timestamp': threat.timestamp.isoformat(),
            'sourceIp': threat.source_ip,
            'logType': threat.get_log_type_display(),
            'threatType': threat.threat_type,
            'severity': threat.get_severity_display(),
            'status': threat.get_status_display()
        })
    
    return result

def export_csv(reports):
    """Export reports as CSV"""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="threat_report.csv"'
    
    writer = csv.writer(response)
    writer.writerow([
        'ID', 'Timestamp', 'Source IP', 'Country', 'Log Type', 
        'Threat Type', 'Severity', 'Status', 'Request Method', 
        'Request Path', 'Status Code', 'User Agent'
    ])
    
    for report in reports:
        writer.writerow([
            report.id, report.timestamp, report.source_ip,
            f"{report.country_name or ''} ({report.country_code or ''})" if report.country_code else "Unknown",
            report.get_log_type_display(), report.threat_type,
            report.get_severity_display(), report.get_status_display(),
            report.request_method, report.request_path,
            report.status_code, report.user_agent
        ])
    
    return response

def export_json(reports):
    """Export reports as JSON"""
    data = []
    
    for report in reports:
        data.append({
            'id': report.id,
            'timestamp': report.timestamp.isoformat(),
            'source_ip': report.source_ip,
            'country_code': report.country_code,
            'country_name': report.country_name,
            'log_type': report.get_log_type_display(),
            'threat_type': report.threat_type,
            'severity': report.get_severity_display(),
            'status': report.get_status_display(),
            'request_method': report.request_method,
            'request_path': report.request_path,
            'status_code': report.status_code,
            'response_size': report.response_size,
            'user_agent': report.user_agent,
            'database': report.database,
            'query_type': report.query_type,
            'raw_log': report.raw_log
        })
    
    response = HttpResponse(json.dumps(data, indent=4), content_type='application/json')
    response['Content-Disposition'] = 'attachment; filename="threat_report.json"'
    return response

def export_pdf(reports, start_date, end_date):
    """Export reports as PDF"""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
        from io import BytesIO
        
        buffer = BytesIO()
        
        # Set document properties to avoid "anonymous" in PDF metadata
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=landscape(letter),
            author="ThreatGuard Admin",  # Set proper author metadata
            title="LogAnalyzer - Threat Report",  # Set proper title metadata
            subject="Security Threat Report"  # Add descriptive subject
        )
        
        elements = []
        
        # Format dates
        start_date_str = start_date.strftime('%Y-%m-%d')
        end_date_str = f"{end_date.date()} 23:59"
        
        # Add title with project name
        styles = getSampleStyleSheet()
        elements.append(Paragraph(f"LogAnalyzer - Threat Report ({start_date_str} to {end_date_str})", styles['Title']))
        elements.append(Spacer(1, 20))
        
        # Create table data
        data = [['ID', 'Timestamp', 'Source IP', 'Log Type', 'Threat Type', 'Severity', 'Status']]
        
        for report in reports[:100]:  # Limit to 100 records to avoid large PDFs
            data.append([
                str(report.id),
                report.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                report.source_ip,
                report.get_log_type_display(),
                report.threat_type,
                report.get_severity_display(),
                report.get_status_display()
            ])
        
        # Create the table
        t = Table(data)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        elements.append(t)
        doc.build(elements)
        
        buffer.seek(0)
        response = HttpResponse(buffer, content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="threat_report.pdf"'
        
        return response
    except ImportError:
        # If reportlab is not installed, fallback to CSV
        return export_csv(reports)

# Add this temporary view to analytics/views.py
def debug_reports(request):
    total = LogReport.objects.count()
    sample_reports = []
    
    for report in LogReport.objects.order_by('-timestamp')[:5]:
        sample_reports.append({
            'id': report.id,
            'timestamp': report.timestamp.isoformat(),
            'log_type': report.log_type,
            'severity': report.severity,
            'threat_type': report.threat_type,
            'source_ip': report.source_ip
        })
    
    return JsonResponse({
        'total_reports': total,
        'sample_reports': sample_reports
    })

def debug_data_view(request):
    """Simple view to check if data exists in database - for debugging only"""
    from django.shortcuts import HttpResponse
    import json
    
    # Check if there's any data in the database
    total_count = LogReport.objects.count()
    
    # Get a sample of the data
    sample = []
    for report in LogReport.objects.all()[:5]:
        sample.append({
            'id': report.id,
            'timestamp': report.timestamp.isoformat() if report.timestamp else None,
            'log_type': report.log_type,
            'severity': report.severity,
            'threat_type': report.threat_type,
            'source_ip': str(report.source_ip),
            'status': report.status
        })
    
    # Return as plain text for easy debugging
    response_data = {
        'total_count': total_count,
        'sample': sample
    }
    
    return HttpResponse(
        f"<pre>{json.dumps(response_data, indent=4)}</pre>", 
        content_type="text/html"
    )
