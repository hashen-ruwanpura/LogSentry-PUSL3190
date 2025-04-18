from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.conf import settings
from django.utils import timezone
from datetime import datetime, timedelta
from log_ingestion.models import LogSource, RawLog, ParsedLog
# Add these missing imports
from threat_detection.models import Threat  # Import for Threat model
from django.db.models import Count, Q  # Import for database aggregation and queries
import logging  # For logging
from django.http import HttpResponse, JsonResponse  # Both response types
import io  # For string IO operations
import csv  # For CSV export
import json
# Fix missing imports
from django.contrib.auth.views import LoginView
from django.urls import reverse_lazy
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

# Configure logger
logger = logging.getLogger(__name__)

class CustomLoginView(LoginView):
    """
    Custom login view that redirects superusers to the admin panel
    and regular users to the dashboard
    """
    template_name = 'registration/login.html'
    
    def get_success_url(self):
        """Determine where to redirect after successful login"""
        # This performs a database check since request.user is loaded from the database
        if self.request.user.is_authenticated and self.request.user.is_superuser:
            return reverse_lazy('admin_home')
        else:
            return reverse_lazy('dashboard')

# Helper function to check if a user is a superuser
def is_superuser(user):
    return user.is_authenticated and user.is_superuser

@login_required
@user_passes_test(is_superuser, login_url='/')
def admin_home(request):
    """
    Admin panel home view with superuser check
    Uses user_passes_test decorator to enforce superuser status from DB
    """
    # Find the correct template path
    template_paths = [
        'frontend/admin/ahome.html',
        'admin/ahome.html'
    ]
    
    # Try each path until one works
    for template_path in template_paths:
        try:
            return render(request, template_path)
        except:
            continue
    
    # If no template is found, return an error
    return render(request, 'error.html', {'message': 'Admin template not found'})

def signup_view(request):
    """
    Handle user registration/signup
    """
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}! You can now log in.')
            return redirect('login')
    else:
        form = UserCreationForm()
    
    return render(request, 'authentication/signup.html', {'form': form})



@login_required
def admin_home(request):
    """
    View for admin home page - accessible only to superusers
    Regular users will be redirected to the home page
    """
    if request.user.is_superuser:
        # User has admin privileges, render admin panel
        return render(request, 'admin/ahome.html')
    else:
        # User doesn't have admin privileges, redirect to regular home
        return redirect('/')

@login_required
def profile_view(request):
    return render(request, 'profile.html')

def contact_view(request):
    return render(request, 'contact.html')

@login_required
def dashboard_view(request):
    """Main dashboard showing key metrics, charts, and handling log viewing/export"""
    # Get time range
    days = request.GET.get('days', 7)
    try:
        days = int(days)
    except ValueError:
        days = 7
    
    start_date = timezone.now() - timezone.timedelta(days=days)
    
    # Handle export requests
    export_type = request.GET.get('export')
    if export_type:
        return export_logs(request, export_type, start_date)
        
    # Handle log viewing requests
    view_type = request.GET.get('view')
    
    # Get dashboard metrics
    try:
        # Get total logs count
        total_logs = ParsedLog.objects.filter(
            timestamp__gte=start_date
        ).count()
        
        # Get Apache specific metrics
        apache_logs = ParsedLog.objects.filter(
            timestamp__gte=start_date,
            source_type='apache'
        )
        apache_count = apache_logs.count()
        apache_errors = apache_logs.filter(status_code__gte=400).count()
        apache_4xx = apache_logs.filter(status_code__gte=400, status_code__lt=500).count()
        apache_5xx = apache_logs.filter(status_code__gte=500).count()
        
        # Get MySQL specific metrics
        mysql_logs = ParsedLog.objects.filter(
            timestamp__gte=start_date,
            source_type='mysql'
        )
        mysql_count = mysql_logs.count()
        mysql_slow = mysql_logs.filter(execution_time__gt=1.0).count()
        
        # Get high severity alerts
        high_level_alerts = Threat.objects.filter(
            created_at__gte=start_date,
            severity__in=['critical', 'high']
        ).count()
        
        # Get authentication metrics
        auth_failures = ParsedLog.objects.filter(
            timestamp__gte=start_date,
            status='authentication_failure'
        ).count()
        
        auth_success = ParsedLog.objects.filter(
            timestamp__gte=start_date,
            status='normal',
            request_path__icontains='login'
        ).count()
        
        # Get recent security alerts
        security_alerts = Threat.objects.filter(
            created_at__gte=start_date
        ).order_by('-created_at')[:10]
        
        # Prepare chart data for alerts evolution
        days_labels = []
        alerts_count = []
        
        for i in range(days, -1, -1):
            day_date = timezone.now() - timezone.timedelta(days=i)
            days_labels.append(day_date.strftime('%d %b'))
            
            day_alert_count = Threat.objects.filter(
                created_at__date=day_date.date()
            ).count()
            alerts_count.append(day_alert_count)
        
        # Get MITRE ATT&CK tactics distribution
        mitre_data = Threat.objects.filter(
            created_at__gte=start_date,
            mitre_tactic__isnull=False
        ).values('mitre_tactic').annotate(
            count=Count('mitre_tactic')
        ).order_by('-count')[:8]
        
        mitre_labels = [item['mitre_tactic'] for item in mitre_data]
        mitre_counts = [item['count'] for item in mitre_data]
        
    except Exception as e:
        # Log the error but continue with mock data
        logger.error(f"Error fetching dashboard data: {e}")
        total_logs = 0
        apache_count = 0
        apache_4xx = 0
        apache_5xx = 0
        mysql_count = 0
        mysql_slow = 0
        high_level_alerts = 0
        auth_failures = 0
        auth_success = 0
        security_alerts = []
        days_labels = [(timezone.now() - timezone.timedelta(days=i)).strftime('%d %b') for i in range(6, -1, -1)]
        alerts_count = [0, 0, 0, 0, 0, 0, 0]
        mitre_labels = []
        mitre_counts = []
    
    context = {
        'total_logs': total_logs,
        'high_level_alerts': high_level_alerts,
        'auth_failures': auth_failures,
        'auth_success': auth_success,
        'security_alerts': security_alerts,
        'chart_labels': json.dumps(days_labels),
        'alerts_data': json.dumps(alerts_count),
        'mitre_labels': json.dumps(mitre_labels),
        'mitre_data': json.dumps(mitre_counts),
        'apache_count': apache_count,
        'apache_errors': apache_errors,
        'apache_4xx': apache_4xx,
        'apache_5xx': apache_5xx,
        'mysql_count': mysql_count,
        'mysql_slow': mysql_slow,
        'days': days
    }
    
    # If viewing logs, add the logs to the context
    if view_type == 'apache_logs':
        apache_logs_list = apache_logs.order_by('-timestamp')[:100]  # Limit to 100 for performance
        context['viewing_logs'] = True
        context['logs'] = apache_logs_list
        context['log_type'] = 'Apache'
    
    elif view_type == 'mysql_logs':
        mysql_logs_list = mysql_logs.order_by('-timestamp')[:100]  # Limit to 100 for performance
        context['viewing_logs'] = True
        context['logs'] = mysql_logs_list
        context['log_type'] = 'MySQL'

    elif view_type == 'search_logs':
        # Get search parameters
        source_type = request.GET.get('source_type', '')
        date_from = request.GET.get('date_from', '')
        date_to = request.GET.get('date_to', '')
        search_query = request.GET.get('search', '')
        
        # Start with all logs
        search_logs = ParsedLog.objects.all()
        
        # Apply filters
        if source_type:
            search_logs = search_logs.filter(source_type=source_type)
        
        if date_from:
            try:
                from_date = timezone.datetime.strptime(date_from, '%Y-%m-%d')
                from_date = timezone.make_aware(from_date)
                search_logs = search_logs.filter(timestamp__gte=from_date)
            except (ValueError, TypeError):
                pass
        
        if date_to:
            try:
                to_date = timezone.datetime.strptime(date_to, '%Y-%m-%d')
                to_date = timezone.make_aware(to_date)
                search_logs = search_logs.filter(timestamp__lte=to_date)
            except (ValueError, TypeError):
                pass
        
        if search_query:
            search_logs = search_logs.filter(
                Q(source_ip__icontains=search_query) |
                Q(request_path__icontains=search_query) |
                Q(query__icontains=search_query) |
                Q(user_id__icontains=search_query)
            )
        
        # Order by timestamp
        search_logs = search_logs.order_by('-timestamp')[:500]  # Limit to 500 for performance
        
        context['viewing_logs'] = True
        context['logs'] = search_logs
        context['log_type'] = 'Search Results'
        context['search_params'] = {
            'source_type': source_type,
            'date_from': date_from,
            'date_to': date_to,
            'search_query': search_query
        }
        
    return render(request, 'authentication/dashboard.html', context)

def export_logs(request, export_type, start_date):
    """Export logs as CSV file"""
    response = HttpResponse(content_type='text/csv')
    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
    
    if export_type == 'apache_logs':
        logs = ParsedLog.objects.filter(timestamp__gte=start_date, source_type='apache').order_by('-timestamp')
        filename = f'apache_logs_{timestamp}.csv'
    elif export_type == 'mysql_logs':
        logs = ParsedLog.objects.filter(timestamp__gte=start_date, source_type='mysql').order_by('-timestamp')
        filename = f'mysql_logs_{timestamp}.csv'
    elif export_type == 'threats':
        # Get specified days or default to 7
        threat_days = request.GET.get('days', 7)
        try:
            threat_days = int(threat_days)
        except ValueError:
            threat_days = 7
            
        threat_start_date = timezone.now() - timezone.timedelta(days=threat_days)
        threats = Threat.objects.filter(created_at__gte=threat_start_date).order_by('-created_at')
        filename = f'security_threats_{timestamp}.csv'
        
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        writer = csv.writer(response)
        writer.writerow([
            'Timestamp', 'Source IP', 'Severity', 'Description', 
            'Status', 'MITRE Tactic', 'MITRE Technique', 
            'Affected System', 'Recommendation'
        ])
        
        for threat in threats:
            writer.writerow([
                threat.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                threat.source_ip,
                threat.severity,
                threat.description,
                threat.status,
                threat.mitre_tactic or '',
                threat.mitre_technique or '',
                threat.affected_system or '',
                threat.recommendation or ''
            ])
        
        return response
    else:
        logs = ParsedLog.objects.filter(timestamp__gte=start_date).order_by('-timestamp')
        filename = f'all_logs_{timestamp}.csv'
    
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    writer = csv.writer(response)
    
    # Write header
    header = ['Timestamp', 'Source Type', 'Source IP', 'Status']
    
    # Add source-specific fields
    if export_type == 'apache_logs':
        header.extend(['Method', 'Path', 'Status Code', 'Response Size', 'User Agent'])
    elif export_type == 'mysql_logs':
        header.extend(['Query', 'Execution Time'])
        
    writer.writerow(header)
    
    # Write data rows
    for log in logs:
        row = [
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.source_type,
            log.source_ip,
            log.status
        ]
        
        if export_type == 'apache_logs':
            row.extend([
                getattr(log, 'request_method', ''),
                getattr(log, 'request_path', ''),
                getattr(log, 'status_code', ''),
                getattr(log, 'response_size', ''),
                getattr(log, 'user_agent', '')
            ])
        elif export_type == 'mysql_logs':
            row.extend([
                getattr(log, 'query', ''),
                getattr(log, 'execution_time', '')
            ])
            
        writer.writerow(row)
    
    return response

@login_required
def generate_report(request):
    """Generate a CSV report of logs or threats"""
    report_type = request.GET.get('type', 'logs')
    source = request.GET.get('source', 'all')  # 'apache', 'mysql', or 'all'
    days = int(request.GET.get('days', 7))
    
    # Set the time range
    start_date = timezone.now() - timezone.timedelta(days=days)
    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
    
    # Create HTTP response with CSV content
    response = HttpResponse(content_type='text/csv')
    
    if report_type == 'logs':
        # Set filename based on source
        if source == 'apache':
            filename = f'apache_logs_{timestamp}.csv'
            logs = ParsedLog.objects.filter(timestamp__gte=start_date, source_type='apache')
        elif source == 'mysql':
            filename = f'mysql_logs_{timestamp}.csv'
            logs = ParsedLog.objects.filter(timestamp__gte=start_date, source_type='mysql')
        else:
            filename = f'all_logs_{timestamp}.csv'
            logs = ParsedLog.objects.filter(timestamp__gte=start_date)
            
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        # Create CSV writer and write header
        writer = csv.writer(response)
        writer.writerow([
            'Timestamp', 'Source Type', 'Source IP', 
            'Request Method', 'Path', 'Status Code', 
            'Response Size', 'User ID', 'Status'
        ])
        
        # Write log data
        for log in logs:
            writer.writerow([
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.source_type,
                log.source_ip,
                getattr(log, 'request_method', ''),
                getattr(log, 'request_path', ''),
                getattr(log, 'status_code', ''),
                getattr(log, 'response_size', ''),
                log.user_id or '',
                log.status
            ])
    
    elif report_type == 'threats':
        filename = f'security_threats_{timestamp}.csv'
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        # Get threats, optionally filtered by source
        if source != 'all':
            threats = Threat.objects.filter(created_at__gte=start_date, parsed_log__source_type=source)
        else:
            threats = Threat.objects.filter(created_at__gte=start_date)
            
        # Create CSV writer and write header
        writer = csv.writer(response)
        writer.writerow([
            'Timestamp', 'Source IP', 'Severity', 
            'Description', 'Status', 'MITRE Tactic', 
            'MITRE Technique', 'Affected System', 'Recommendation'
        ])
        
        # Write threat data
        for threat in threats:
            writer.writerow([
                threat.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                threat.source_ip,
                threat.severity,
                threat.description,
                threat.status,
                threat.mitre_tactic,
                threat.mitre_technique,
                threat.affected_system,
                threat.recommendation
            ])
            
    return response

def logout_view(request):
    """Handle user logout"""
    logout(request)
    messages.info(request, 'You have been successfully logged out.')
    return redirect('login')

@login_required
def events_view(request):
    """View for events page"""
    return render(request, 'authentication/events.html')

@login_required
def apache_logs_view(request):
    """View for Apache logs page"""
    return render(request, 'authentication/apache_logs.html')

@login_required
def mysql_logs_view(request):
    """View for MySQL logs page"""
    return render(request, 'authentication/mysql_logs.html')

@login_required
def reports_view(request):
    """View for AI reports page"""
    return render(request, 'frontend/templates/reports.html')

@login_required
def settings_view(request):
    """View for settings page with form handling"""
    # Get user settings if they exist
    user = request.user
    
    if request.method == 'POST':
        # Handle form submissions from settings page
        form_type = request.POST.get('form_type', '')
        
        if form_type == 'notification_settings':
            # Process notification settings
            email_notifications = request.POST.get('email_notifications') == 'on'
            critical_alerts = request.POST.get('critical_alerts') == 'on'
            warning_alerts = request.POST.get('warning_alerts') == 'on'
            system_notifications = request.POST.get('system_notifications') == 'on'
            
            # Here you would save these settings to the user's profile or a settings model
            # Example: user.profile.email_notifications = email_notifications
            # user.profile.save()
            
            messages.success(request, 'Notification settings updated successfully.')
            
        elif form_type == 'security_settings':
            # Process security settings
            two_factor = request.POST.get('two_factor') == 'on'
            session_timeout = request.POST.get('session_timeout')
            login_history = request.POST.get('login_history') == 'on'
            
            # Save security settings
            messages.success(request, 'Security settings updated successfully.')
            
        elif form_type == 'log_settings':
            # Process log collection settings
            apache_log_path = request.POST.get('apache_log_path')
            mysql_log_path = request.POST.get('mysql_log_path')
            log_retention = request.POST.get('log_retention')
            scan_frequency = request.POST.get('scan_frequency')
            
            # Save log settings
            messages.success(request, 'Log collection settings updated successfully.')
            
        elif form_type == 'smtp_settings':
            # Process SMTP settings
            smtp_server = request.POST.get('smtp_server')
            smtp_port = request.POST.get('smtp_port')
            smtp_username = request.POST.get('smtp_username')
            smtp_password = request.POST.get('smtp_password')
            
            # Save SMTP settings
            messages.success(request, 'SMTP settings updated successfully.')
    
    # Prepare context with settings data
    # For a real implementation, you would load these from the user's profile or settings model
    context = {
        'notification_settings': {
            'email_notifications': True,
            'critical_alerts': True,
            'warning_alerts': True,
            'system_notifications': False,
        },
        'security_settings': {
            'two_factor': False,
            'session_timeout': 30,
            'login_history': True,
        },
        'log_settings': {
            'apache_log_path': '/var/log/apache2/',
            'mysql_log_path': '/var/log/mysql/',
            'log_retention': 30,
            'scan_frequency': 5,
        },
        'smtp_settings': {
            'smtp_server': '',
            'smtp_port': 587,
            'smtp_username': '',
            'smtp_password': '',
        }
    }
    
    return render(request, 'authentication/settings.html', context)

@login_required
def explore_agent_view(request):
    """View for exploring agent"""
    return render(request, 'authentication/explore_agent.html')

@login_required
def generate_report_view(request):
    """View for generating reports"""
    # This could potentially process a report generation and return a file
    return render(request, 'authentication/generate_report.html')

@login_required
def alerts_details_view(request):
    """View for detailed alerts"""
    return render(request, 'authentication/alerts_details.html')

@login_required
def mitre_details_view(request):
    """View for MITRE ATT&CK details"""
    return render(request, 'authentication/mitre_details.html')

@login_required
def events_view(request):
    """View for security events page with filtering"""
    # Get filter parameters from request
    event_type = request.GET.get('event_type', 'all')
    severity = request.GET.get('severity', 'all')
    time_period = request.GET.get('time_period', '24h')
    search = request.GET.get('search', '')
    
    # Determine time range based on selected period
    if time_period == '7d':
        start_time = timezone.now() - timedelta(days=7)
    elif time_period == '30d':
        start_time = timezone.now() - timedelta(days=30)
    else:  # Default to 24 hours
        start_time = timezone.now() - timedelta(hours=24)
    
    # Start with all logs in the selected time period
    events = ParsedLog.objects.filter(timestamp__gte=start_time).order_by('-timestamp')
    
    # Apply event type filter
    if event_type != 'all':
        if event_type == 'security':
            events = events.filter(log_level__gte=7)  # Assuming security events are high severity
        elif event_type == 'access':
            events = events.filter(request_method__isnull=False)  # Assuming access logs have request methods
        elif event_type == 'error':
            events = events.filter(log_level__range=(4, 6))  # Medium severity
        elif event_type == 'system':
            events = events.filter(log_level__lte=3)  # Low severity
    
    # Apply severity filter
    if severity != 'all':
        if severity == 'high':
            events = events.filter(log_level__gte=7)
        elif severity == 'medium':
            events = events.filter(log_level__range=(4, 6))
        elif severity == 'low':
            events = events.filter(log_level__range=(2, 3))
        elif severity == 'info':
            events = events.filter(log_level__lte=1)
    
    # Apply search filter if provided
    if search:
        events = events.filter(normalized_data__icontains=search)
    
    # Count total before pagination
    total_events = events.count()
    
    # Paginate results
    paginator = Paginator(events, 20)  # 20 events per page
    page_number = request.GET.get('page', 1)
    events_page = paginator.get_page(page_number)
    
    # Transform ParsedLog objects to dictionaries with event-specific fields for the template
    formatted_events = []
    for log in events_page:
        # Determine event type
        if log.log_level >= 7:
            event_type = "Security"
        elif hasattr(log, 'request_method') and log.request_method:
            event_type = "Access"
        elif log.log_level >= 4:
            event_type = "Error"
        else:
            event_type = "System"
            
        # Determine severity
        if log.log_level >= 7:
            severity = "High"
        elif log.log_level >= 4:
            severity = "Medium"
        elif log.log_level >= 2:
            severity = "Low"
        else:
            severity = "Info"
            
        # Get source type
        source_type = "unknown"
        if hasattr(log, 'source') and log.source:
            try:
                source = LogSource.objects.get(id=log.source.id)
                source_type = source.source_type
            except LogSource.DoesNotExist:
                pass
                
        # Format event for template
        event = {
            'id': log.id,
            'timestamp': log.timestamp,
            'event_type': event_type,
            'source_type': source_type,
            'source': getattr(log, 'source_ip', None) or getattr(log.source, 'name', 'Unknown'),
            'description': log.normalized_data or "No description available",
            'severity': severity,
            'user': getattr(log, 'user_id', None),
            'ip_address': getattr(log, 'source_ip', None),
            'status_code': getattr(log, 'status_code', None),
            'threat_type': getattr(log, 'threat', None),
            'mitre_id': getattr(log, 'mitre_id', None),
            'mitre_tactic': None,  # This would need to be added to your model
            'raw_content': None  # You would need to add this field or pull from RawLog
        }
        formatted_events.append(event)
    
    context = {
        'events': formatted_events,
        'total_events': total_events,
        'event_type': event_type,
        'severity': severity,
        'time_period': time_period,
        'search': search,
    }
    
    return render(request, 'authentication/events.html', context)

@login_required
def export_events(request):
    """Export events as CSV based on filters"""
    # Get filter parameters from request - same as events_view
    event_type = request.GET.get('event_type', 'all')
    severity = request.GET.get('severity', 'all')
    time_period = request.GET.get('time_period', '24h')
    search = request.GET.get('search', '')
    
    # Apply same filtering logic as events_view
    if time_period == '7d':
        start_time = timezone.now() - timedelta(days=7)
    elif time_period == '30d':
        start_time = timezone.now() - timedelta(days=30)
    else:
        start_time = timezone.now() - timedelta(hours=24)
    
    events = ParsedLog.objects.filter(timestamp__gte=start_time).order_by('-timestamp')
    
    # Apply filters (same as in events_view)
    # [Filter code here]
    
    # Create CSV response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="security_events.csv"'
    
    # Create CSV writer
    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    
    # Write header row
    writer.writerow(['Timestamp', 'Event Type', 'Source', 'Description', 'Severity', 'User', 'IP Address'])
    
    # Write data rows
    for log in events:
        # Determine event type and severity same as in events_view
        # [Code to determine event_type and severity]
        
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            event_type,
            getattr(log.source, 'name', 'Unknown'),
            log.normalized_data,
            severity,
            getattr(log, 'user_id', ''),
            getattr(log, 'source_ip', '')
        ])
    
    response.write(csv_buffer.getvalue())
    return response

@login_required
def explore_logs(request):
    """Advanced log search and exploration interface"""
    # Get filter parameters
    source_type = request.GET.get('source_type', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    status_code = request.GET.get('status_code', '')
    search_query = request.GET.get('search', '')
    
    # Start with all logs
    logs = ParsedLog.objects.all().order_by('-timestamp')
    
    # Apply filters
    if source_type:
        logs = logs.filter(source_type=source_type)
    
    if date_from:
        try:
            from_date = timezone.datetime.strptime(date_from, '%Y-%m-%d')
            from_date = timezone.make_aware(from_date)
            logs = logs.filter(timestamp__gte=from_date)
        except (ValueError, TypeError):
            pass
    
    if date_to:
        try:
            to_date = timezone.datetime.strptime(date_to, '%Y-%m-%d')
            to_date = timezone.make_aware(to_date)
            logs = logs.filter(timestamp__lte=to_date)
        except (ValueError, TypeError):
            pass
    
    if status_code:
        logs = logs.filter(status_code=status_code)
    
    if search_query:
        logs = logs.filter(
            Q(source_ip__icontains=search_query) |
            Q(request_path__icontains=search_query) |
            Q(query__icontains=search_query) |
            Q(user_id__icontains=search_query)
        )
    
    # Paginate results
    page = request.GET.get('page', 1)
    paginator = Paginator(logs, 50)  # 50 logs per page
    
    try:
        logs_page = paginator.page(page)
    except PageNotAnInteger:
        logs_page = paginator.page(1)
    except EmptyPage:
        logs_page = paginator.page(paginator.num_pages)
    
    context = {
        'logs': logs_page,
        'source_type': source_type,
        'date_from': date_from,
        'date_to': date_to,
        'status_code': status_code,
        'search_query': search_query,
    }
    
    return render(request, 'authentication/explore_logs.html', context)

@login_required
def alert_detail(request, alert_id):
    """View detailed information about a security alert"""
    alert = get_object_or_404(Threat, id=alert_id)
    
    # Get associated log info if available
    log_info = None
    if alert.parsed_log:
        log_info = {
            'timestamp': alert.parsed_log.timestamp,
            'source_ip': alert.parsed_log.source_ip,
            'request_path': getattr(alert.parsed_log, 'request_path', None),
            'request_method': getattr(alert.parsed_log, 'request_method', None),
            'status_code': getattr(alert.parsed_log, 'status_code', None),
            'user_agent': getattr(alert.parsed_log, 'user_agent', None),
            'query': getattr(alert.parsed_log, 'query', None),
            'execution_time': getattr(alert.parsed_log, 'execution_time', None),
            'source_type': alert.parsed_log.source_type,
        }
    
    context = {
        'alert': alert,
        'log_info': log_info,
    }
    
    return render(request, 'authentication/alert_detail.html', context)

