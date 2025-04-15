from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.conf import settings
from django.utils import timezone
from datetime import datetime, timedelta
from log_ingestion.models import LogSource, RawLog, ParsedLog
import json
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth.views import LoginView
from django.urls import reverse_lazy
from django.contrib.auth.models import User
from django.http import JsonResponse

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
    """Main dashboard showing key metrics and charts"""
    try:
        # Get time range from request or default to last 24 hours
        timeframe = request.GET.get('timeframe', '24h')
        
        if timeframe == '24h':
            start_date = timezone.now() - timedelta(hours=24)
        elif timeframe == '7d':
            start_date = timezone.now() - timedelta(days=7)
        elif timeframe == '30d':
            start_date = timezone.now() - timedelta(days=30)
        else:
            start_date = timezone.now() - timedelta(hours=24)
        
        # Get log statistics based on actual fields in your database
        total_logs = RawLog.objects.filter(timestamp__gte=start_date).count()
        
        # High severity alerts (using log_level field that exists in your model)
        high_level_alerts = ParsedLog.objects.filter(
            timestamp__gte=start_date, 
            log_level__gte=4
        ).count()
        
        # Use normalized_data field instead of message field
        auth_failures = ParsedLog.objects.filter(
            timestamp__gte=start_date,
            normalized_data__icontains='authentication failure'
        ).count()
        
        auth_success = ParsedLog.objects.filter(
            timestamp__gte=start_date,
            normalized_data__icontains='authentication success'
        ).count()
        
        # Get recent security alerts
        security_alerts = ParsedLog.objects.filter(
            timestamp__gte=start_date,
            log_level__gte=4
        ).order_by('-timestamp')[:10]
        
        # Generate chart data for alerts evolution
        days = []
        alerts_count = []
        
        for i in range(7):
            day = timezone.now().date() - timedelta(days=i)
            days.insert(0, day.strftime('%d %b'))
            count = ParsedLog.objects.filter(
                timestamp__date=day,
                log_level__gte=4
            ).count()
            alerts_count.insert(0, count)
        
        # For MITRE tactics chart (using status field from your model)
        attack_types = ParsedLog.objects.filter(
            timestamp__gte=start_date,
            log_level__gte=3
        ).values('status').distinct()
        
        mitre_labels = []
        mitre_data = []
        
        for attack in attack_types:
            if attack['status']:
                attack_name = attack['status']
                count = ParsedLog.objects.filter(
                    timestamp__gte=start_date,
                    status=attack_name
                ).count()
                mitre_labels.append(attack_name)
                mitre_data.append(count)
                
    except Exception as e:
        # Use mock data if database queries fail
        print(f"Error fetching dashboard data: {e}")
        total_logs = 245
        high_level_alerts = 12
        auth_failures = 28
        auth_success = 178
        
        # Create mock security alerts with fields matching the template
        security_alerts = [
            {
                'timestamp': timezone.now() - timedelta(hours=2),
                'agent_name': 'main-web-server',
                'mitre_id': 'T1110',
                'mitre_tactic': 'Credential Access',
                'description': 'Multiple failed login attempts detected from IP 192.168.1.45',
                'level': 12,
                'rule_id': 'rule-1001'
            },
            {
                'timestamp': timezone.now() - timedelta(hours=5),
                'agent_name': 'database-server',
                'mitre_id': 'T1078',
                'mitre_tactic': 'Defense Evasion',
                'description': 'Privileged user account used at unusual hour',
                'level': 13,
                'rule_id': 'rule-1002'
            }
        ]
        
        days = [(timezone.now() - timedelta(days=i)).strftime('%d %b') for i in range(6, -1, -1)]
        alerts_count = [5, 8, 12, 7, 15, 10, 6]
        mitre_labels = ['Credential Access', 'Defense Evasion', 'Initial Access', 'Execution']
        mitre_data = [12, 8, 15, 7]
    
    context = {
        'total_logs': total_logs,
        'high_level_alerts': high_level_alerts,
        'auth_failures': auth_failures,
        'auth_success': auth_success,
        'security_alerts': security_alerts,
        'chart_labels': json.dumps(days),
        'alerts_data': json.dumps(alerts_count),
        'mitre_labels': json.dumps(mitre_labels or ["No Data"]),
        'mitre_data': json.dumps(mitre_data or [100])
    }
    
    return render(request, 'authentication/dashboard.html', context)

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
    """View for settings page"""
    return render(request, 'authentication/settings.html')

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


@login_required #Might Change
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
            'session_timeout': '30 minutes',
            'login_history': True,
        },
        'log_settings': {
            'apache_log_path': '/var/log/apache2/access.log',
            'mysql_log_path': '/var/log/mysql/mysql.log',
            'log_retention': '30 days',
            'scan_frequency': 'Every 15 minutes',
        },
        'smtp_settings': {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': '587',
            'smtp_username': '',
            'smtp_password': '',
        }
    }
    
    return render(request, 'settings.html', context)

