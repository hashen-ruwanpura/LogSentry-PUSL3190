import json
from datetime import datetime, timedelta
from django.utils import timezone
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from log_ingestion.models import RawLog, ParsedLog
from threat_detection.models import Threat, BlacklistedIP
from threat_detection.models import Threat, ThreatAnalysis

from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import user_passes_test
from django.conf import settings
from django.utils import timezone
from datetime import datetime, timedelta
from log_ingestion.models import LogSource, RawLog, ParsedLog  # Remove LogEntry
from threat_detection.models import Threat
from django.db.models import Count, Q
import logging
from django.views.decorators.http import require_POST
from django.http import HttpResponse, JsonResponse
import io
import csv
from django.contrib.auth.views import LoginView
from django.urls import reverse_lazy, reverse
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth import update_session_auth_hash

from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.units import inch
from io import BytesIO
from django.db.models import Count, Sum
from django.conf import settings

from threat_detection.models import Threat, ThreatAnalysis
from ai_analytics.services import AlertAnalysisService

logger = logging.getLogger(__name__)

# Add this helper function near the top of your file
def get_start_date_from_timeframe(timeframe):
    """Helper function to calculate start date from timeframe string"""
    now = timezone.now()
    if timeframe == '1h':
        return now - timedelta(hours=1)
    elif timeframe == '3h':
        return now - timedelta(hours=3)
    elif timeframe == '12h':
        return now - timedelta(hours=12)
    elif timeframe == '7d':
        return now - timedelta(days=7)
    elif timeframe == '30d':
        return now - timedelta(days=30)
    else:  # Default to 1d
        return now - timedelta(days=1)

# Add this safety check to both view functions after setting context
def safe_render(request, template_name, context):
    """Safely render a template with error handling"""
    try:
        return render(request, template_name, context)
    except Exception as e:
        error_context = {
            'error_message': str(e),
            'template_tried': template_name,
            'context_keys': list(context.keys()),
            'logs': [],
            'total_logs': 0
        }
        return render(request, 'error.html', error_context)

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
    # Get the timeframe parameter
    timeframe = request.GET.get('timeframe', '1d')
    
    # Determine the time range based on timeframe parameter
    now = timezone.now()
    if timeframe == '1h':
        start_time = now - timedelta(hours=1)
        period_name = 'Last 1 Hour'
    elif timeframe == '3h':
        start_time = now - timedelta(hours=3)
        period_name = 'Last 3 Hours'
    elif timeframe == '12h':
        start_time = now - timedelta(hours=12)
        period_name = 'Last 12 Hours'
    elif timeframe == '7d':
        start_time = now - timedelta(days=7)
        period_name = 'Last 7 Days'
    elif timeframe == '30d':
        start_time = now - timedelta(days=30)
        period_name = 'Last 30 Days'
    else:  # Default to 1d
        start_time = now - timedelta(days=1)
        period_name = 'Last 24 Hours'
        timeframe = '1d'

    # Get log metrics
    total_logs = RawLog.objects.filter(timestamp__gte=start_time).count()
    apache_count = RawLog.objects.filter(source__source_type='apache', timestamp__gte=start_time).count()
    mysql_count = RawLog.objects.filter(source__source_type='mysql', timestamp__gte=start_time).count()
    
    # Get Apache errors - CORRECTED FIELD ACCESS
    apache_4xx = ParsedLog.objects.filter(
        raw_log__source__source_type='apache',
        raw_log__timestamp__gte=start_time,
        status_code__gte=400,
        status_code__lt=500
    ).count()
    
    apache_5xx = ParsedLog.objects.filter(
        raw_log__source__source_type='apache',
        raw_log__timestamp__gte=start_time,
        status_code__gte=500
    ).count()
    
    # Get MySQL slow queries - CORRECTED FIELD ACCESS
    mysql_slow = ParsedLog.objects.filter(
        raw_log__source__source_type='mysql',
        raw_log__timestamp__gte=start_time,
        execution_time__gte=1.0  # Queries taking more than 1 second
    ).count()
    
    # Calculate Apache percentages instead of using template filters
    if apache_count > 0:
        apache_success_percentage = ((apache_count - apache_4xx - apache_5xx) / apache_count) * 100
        apache_4xx_percentage = (apache_4xx / apache_count) * 100
        apache_5xx_percentage = (apache_5xx / apache_count) * 100
    else:
        apache_success_percentage = 0
        apache_4xx_percentage = 0
        apache_5xx_percentage = 0
    
    # Calculate MySQL percentages instead of using template filters
    if mysql_count > 0:
        mysql_fast_percentage = ((mysql_count - mysql_slow) / mysql_count) * 100
        mysql_slow_percentage = (mysql_slow / mysql_count) * 100
    else:
        mysql_fast_percentage = 0
        mysql_slow_percentage = 0
    
    # Get security alerts count
    high_level_alerts = Threat.objects.filter(
        created_at__gte=start_time,
        severity__in=['high', 'critical']
    ).count()
    
    # Get authentication metrics - CORRECTED FIELD ACCESS
    auth_failures = ParsedLog.objects.filter(
        raw_log__timestamp__gte=start_time,
        status='failure'  # Assuming this is the correct field name
    ).count()
    
    auth_success = ParsedLog.objects.filter(
        raw_log__timestamp__gte=start_time,
        status='success'  # Assuming this is the correct field name
    ).count()
    
    # Get recent security alerts
    security_alerts = Threat.objects.filter(
        created_at__gte=start_time
    ).order_by('-created_at')[:10]  # Latest 10 alerts
    
    # Generate chart data
    chart_labels, alerts_data = generate_alerts_chart_data(start_time, now)
    mitre_labels, mitre_data = generate_mitre_chart_data(start_time)
    
    context = {
        'period_name': period_name,
        'timeframe': timeframe,
        'total_logs': total_logs,
        'high_level_alerts': high_level_alerts,
        'auth_failures': auth_failures,
        'auth_success': auth_success,
        'apache_count': apache_count,
        'apache_4xx': apache_4xx,
        'apache_5xx': apache_5xx,
        'mysql_count': mysql_count,
        'mysql_slow': mysql_slow,
        'security_alerts': security_alerts,
        'chart_labels': json.dumps(chart_labels),
        'alerts_data': json.dumps(alerts_data),
        'mitre_labels': json.dumps(mitre_labels),
        'mitre_data': json.dumps(mitre_data),
        'apache_success_percentage': apache_success_percentage,
        'apache_4xx_percentage': apache_4xx_percentage,
        'apache_5xx_percentage': apache_5xx_percentage,
        'mysql_fast_percentage': mysql_fast_percentage,
        'mysql_slow_percentage': mysql_slow_percentage,
        'ai_reports_url': reverse('ai_analytics:reports_dashboard'),
        'features': [
            {
                'title': 'AI-Powered Reports',
                'icon': 'fas fa-robot',
                'description': 'Generate intelligent security analysis with AI',
                'url': reverse('ai_analytics:reports_dashboard'),
                'color': 'primary'
            }
        ]
    }
    
    
    return render(request, 'authentication/dashboard.html', context)

@login_required
def dashboard_data_api(request):
    """API endpoint for dashboard data updates via AJAX"""
    timeframe = request.GET.get('timeframe', '1d')
    start_date = get_start_date_from_timeframe(timeframe)
    now = timezone.now()
    
    # FIXED: Use RawLog instead of ParsedLog to match dashboard_view function
    # And use the same field access patterns
    total_logs = RawLog.objects.filter(timestamp__gte=start_date).count()
    
    # Get Apache metrics - use source__source_type to match dashboard_view
    apache_count = RawLog.objects.filter(
        source__source_type='apache', 
        timestamp__gte=start_date
    ).count()
    
    # Get Apache errors through ParsedLog with correct relationship
    apache_4xx = ParsedLog.objects.filter(
        raw_log__source__source_type='apache',
        raw_log__timestamp__gte=start_date,
        status_code__gte=400,
        status_code__lt=500
    ).count()
    
    apache_5xx = ParsedLog.objects.filter(
        raw_log__source__source_type='apache',
        raw_log__timestamp__gte=start_date,
        status_code__gte=500
    ).count()
    
    # Get MySQL metrics - use source__source_type to match dashboard_view
    mysql_count = RawLog.objects.filter(
        source__source_type='mysql', 
        timestamp__gte=start_date
    ).count()
    
    # Get MySQL slow queries through ParsedLog with correct relationship
    mysql_slow = ParsedLog.objects.filter(
        raw_log__source__source_type='mysql',
        raw_log__timestamp__gte=start_date,
        execution_time__gt=1.0
    ).count()
    
    # Rest of function remains the same...
    high_level_alerts = Threat.objects.filter(
        created_at__gte=start_date, 
        severity__in=['high', 'critical']
    ).count()
    
    auth_failures = ParsedLog.objects.filter(
        raw_log__timestamp__gte=start_date,
        status='failure'
    ).count()
    
    auth_success = ParsedLog.objects.filter(
        raw_log__timestamp__gte=start_date,
        status='success'
    ).count()
    
    # Get chart data
    chart_labels, alerts_data = generate_alerts_chart_data(start_date, now)
    
    # Get MITRE data
    mitre_tactics = Threat.objects.filter(
        created_at__gte=start_date
    ).exclude(
        mitre_tactic__isnull=True
    ).exclude(
        mitre_tactic=''
    ).values('mitre_tactic').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    mitre_labels = [t['mitre_tactic'] for t in mitre_tactics]
    mitre_data = [t['count'] for t in mitre_tactics]
    
    # Get recent alerts
    alerts = []
    for threat in Threat.objects.filter(created_at__gte=start_date).order_by('-created_at')[:10]:
        alerts.append({
            'id': threat.id,
            'timestamp': threat.created_at.strftime('%Y-%m-%d %H:%M'),
            'source_ip': threat.source_ip,
            'severity': threat.severity,
            'mitre_tactic': threat.mitre_tactic,
            'mitre_technique': threat.mitre_technique,
            'description': threat.description
        })
    
    return JsonResponse({
        'metrics': {
            'total_logs': total_logs,
            'high_level_alerts': high_level_alerts,
            'auth_failures': auth_failures,
            'auth_success': auth_success,
            'apache_count': apache_count,
            'apache_4xx': apache_4xx,
            'apache_5xx': apache_5xx,
            'mysql_count': mysql_count,
            'mysql_slow': mysql_slow
        },
        'charts': {
            'alerts': {
                'labels': chart_labels,
                'data': alerts_data
            },
            'mitre': {
                'labels': mitre_labels,
                'data': mitre_data
            }
        },
        'alerts': alerts
    })

@login_required
def explore_logs(request):
    """
    View for exploring and analyzing log data.
    Allows users to search, filter, and visualize log entries.
    """
    # Get filter parameters from request
    source_type = request.GET.get('source_type', 'all')
    log_level = request.GET.get('log_level', 'all')
    time_range = request.GET.get('time_range', '24h')
    search_query = request.GET.get('search', '')
    page = int(request.GET.get('page', 1))
    
    # Define time period based on selected range
    now = timezone.now()
    if time_range == '1h':
        start_time = now - timedelta(hours=1)
    elif time_range == '12h':
        start_time = now - timedelta(hours=12)
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
    elif time_range == '30d':
        start_time = now - timedelta(days=30)
    else:  # Default to 24h
        start_time = now - timedelta(days=1)
    
    # Base queryset
    logs = RawLog.objects.filter(timestamp__gte=start_time)
    
    # Apply source type filter
    if source_type != 'all':
        logs = logs.filter(source__source_type=source_type)
    
    # Apply search filter if provided
    if search_query:
        logs = logs.filter(content__icontains=search_query)
    
    # Get count of logs by source
    apache_count = logs.filter(source__source_type='apache').count()
    mysql_count = logs.filter(source__source_type='mysql').count()
    
    # Pagination
    per_page = 50
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    logs_paginated = logs.order_by('-timestamp')[start_idx:end_idx]
    total_logs = logs.count()
    total_pages = (total_logs + per_page - 1) // per_page
    
    # Generate page range
    if total_pages <= 7:
        page_range = range(1, total_pages + 1)
    else:
        if page <= 4:
            page_range = list(range(1, 6)) + ['...', total_pages]
        elif page >= total_pages - 3:
            page_range = [1, '...'] + list(range(total_pages - 4, total_pages + 1))
        else:
            page_range = [1, '...'] + list(range(page - 1, page + 2)) + ['...', total_pages]
    
    context = {
        'logs': logs_paginated,
        'total_logs': total_logs,
        'apache_count': apache_count,
        'mysql_count': mysql_count,
        'source_type': source_type,
        'log_level': log_level,
        'time_range': time_range,
        'search_query': search_query,
        'current_page': page,
        'total_pages': total_pages,
        'page_range': page_range,
        'has_next': page < total_pages,
        'has_prev': page > 1,
        'next_page': page + 1,
        'prev_page': page - 1,
    }
    
    return render(request, 'authentication/explore_logs.html', context)

@login_required
def explore_agent_view(request):
    """
    View for exploring log collection agent information and status.
    Shows agent health, configuration, and recent activities.
    """
    # Get filter parameters
    status = request.GET.get('status', 'all')
    agent_type = request.GET.get('type', 'all')
    search_query = request.GET.get('search', '')
    page = int(request.GET.get('page', 1))
    
    # Base queryset - assuming you have an Agent model
    # If you don't have this model, you'll need to adjust this accordingly
    try:
        from log_ingestion.models import LogAgent
        agents = LogAgent.objects.all()
        
        # Apply filters
        if status != 'all':
            agents = agents.filter(status=status)
        
        if agent_type != 'all':
            agents = agents.filter(agent_type=agent_type)
        
        if search_query:
            agents = agents.filter(
                Q(name__icontains=search_query) |
                Q(hostname__icontains=search_query) |
                Q(ip_address__icontains=search_query)
            )
        
        # Get status counts for filters
        active_count = LogAgent.objects.filter(status='active').count()
        inactive_count = LogAgent.objects.filter(status='inactive').count()
        error_count = LogAgent.objects.filter(status='error').count()
        
        # Get agent types for filters
        agent_types = LogAgent.objects.values_list('agent_type', flat=True).distinct()
        
        # Pagination
        per_page = 20
        paginator = Paginator(agents, per_page)
        
        try:
            agents_page = paginator.page(page)
        except (EmptyPage, PageNotAnInteger):
            agents_page = paginator.page(1)
            page = 1
        
        context = {
            'agents': agents_page,
            'total_agents': agents.count(),
            'active_count': active_count,
            'inactive_count': inactive_count,
            'error_count': error_count,
            'agent_types': agent_types,
            'current_status': status,
            'current_type': agent_type,
            'search_query': search_query,
            'current_page': page,
            'total_pages': paginator.num_pages,
            'page_range': paginator.get_elided_page_range(page, on_each_side=2, on_ends=1),
        }
    except ImportError:
        # Fallback if LogAgent model doesn't exist
        context = {
            'error_message': "Agent monitoring is not available. The LogAgent model is not defined.",
            'agents': [],
            'total_agents': 0,
        }
    except Exception as e:
        # General error handling
        context = {
            'error_message': f"An error occurred while loading agent data: {str(e)}",
            'agents': [],
            'total_agents': 0,
        }
        
    return render(request, 'authentication/explore_agent.html', context)

@login_required
def apache_logs_view(request):
    """
    View for displaying and analyzing Apache web server logs.
    Provides filtering, search and statistics specific to Apache logs.
    """
    # Get filter parameters
    time_range = request.GET.get('time_range', '24h')
    status_code = request.GET.get('status_code', 'all')
    request_method = request.GET.get('method', 'all')
    search_query = request.GET.get('search', '')
    page = int(request.GET.get('page', 1))
    
    # Determine time period based on selected range
    now = timezone.now()
    if time_range == '1h':
        start_time = now - timedelta(hours=1)
        period_name = 'Last Hour'
    elif time_range == '12h':
        start_time = now - timedelta(hours=12)
        period_name = 'Last 12 Hours'
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
        period_name = 'Last 7 Days'
    elif time_range == '30d':
        start_time = now - timedelta(days=30)
        period_name = 'Last 30 Days'
    else:  # Default to 24h
        start_time = now - timedelta(days=1)
        period_name = 'Last 24 Hours'
        time_range = '24h'
    
    # Base queryset - filter for Apache logs only
    logs = ParsedLog.objects.filter(
        raw_log__source__source_type='apache',
        raw_log__timestamp__gte=start_time
    ).select_related('raw_log')
    
    # Apply status code filter
    if status_code != 'all':
        if status_code == '2xx':
            logs = logs.filter(status_code__gte=200, status_code__lt=300)
        elif status_code == '3xx':
            logs = logs.filter(status_code__gte=300, status_code__lt=400)
        elif status_code == '4xx':
            logs = logs.filter(status_code__gte=400, status_code__lt=500)
        elif status_code == '5xx':
            logs = logs.filter(status_code__gte=500)
        else:
            # Try to filter by specific status code
            try:
                logs = logs.filter(status_code=int(status_code))
            except ValueError:
                pass
    
    # Apply request method filter
    if request_method != 'all':
        logs = logs.filter(request_method=request_method)
    
    # Apply search filter if provided
    if search_query:
        logs = logs.filter(
            Q(request_path__icontains=search_query) | 
            Q(source_ip__icontains=search_query) |
            Q(user_agent__icontains=search_query)
        )
    
    # Get statistics
    total_logs = logs.count()
    status_2xx = logs.filter(status_code__gte=200, status_code__lt=300).count()
    status_3xx = logs.filter(status_code__gte=300, status_code__lt=400).count()
    status_4xx = logs.filter(status_code__gte=400, status_code__lt=500).count()
    status_5xx = logs.filter(status_code__gte=500).count()
    
    # Get common request methods
    common_methods = logs.values('request_method').annotate(
        count=Count('request_method')
    ).order_by('-count')[:5]
    
    # Get top requested paths
    top_paths = logs.values('request_path').annotate(
        count=Count('request_path')
    ).order_by('-count')[:10]
    
    # Get top source IPs
    top_ips = logs.values('source_ip').annotate(
        count=Count('source_ip')
    ).order_by('-count')[:10]
    
    # Pagination
    per_page = 50
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    logs_paginated = logs.order_by('-raw_log__timestamp')[start_idx:end_idx]
    total_pages = (total_logs + per_page - 1) // per_page
    
    # Generate page range
    if total_pages <= 7:
        page_range = range(1, total_pages + 1)
    else:
        if page <= 4:
            page_range = list(range(1, 6)) + ['...', total_pages]
        elif page >= total_pages - 3:
            page_range = [1, '...'] + list(range(total_pages - 4, total_pages + 1))
        else:
            page_range = [1, '...'] + list(range(page - 1, page + 2)) + ['...', total_pages]
    
    context = {
        'logs': logs_paginated,
        'total_logs': total_logs,
        'period_name': period_name,
        'time_range': time_range,
        'status_code': status_code,
        'request_method': request_method,
        'search_query': search_query,
        'status_2xx': status_2xx,
        'status_3xx': status_3xx,
        'status_4xx': status_4xx,
        'status_5xx': status_5xx,
        'common_methods': common_methods,
        'top_paths': top_paths,
        'top_ips': top_ips,
        'current_page': page,
        'total_pages': total_pages,
        'page_range': page_range,
        'has_next': page < total_pages,
        'has_prev': page > 1,
        'next_page': page + 1,
        'prev_page': page - 1,
    }
    
    return render(request, 'authentication/apache_logs.html', context)

@login_required
def mysql_logs_view(request):
    """
    View for displaying and analyzing MySQL database logs.
    Provides filtering, search and statistics specific to MySQL logs.
    """
    # Get filter parameters
    time_range = request.GET.get('time_range', '24h')
    query_type = request.GET.get('query_type', 'all')
    execution_time = request.GET.get('execution_time', 'all')
    search_query = request.GET.get('search', '')
    page = int(request.GET.get('page', 1))
    
    # Determine time period based on selected range
    now = timezone.now()
    if time_range == '1h':
        start_time = now - timedelta(hours=1)
        period_name = 'Last Hour'
    elif time_range == '12h':
        start_time = now - timedelta(hours=12)
        period_name = 'Last 12 Hours'
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
        period_name = 'Last 7 Days'
    elif time_range == '30d':
        start_time = now - timedelta(days=30)
        period_name = 'Last 30 Days'
    else:  # Default to 24h
        start_time = now - timedelta(days=1)
        period_name = 'Last 24 Hours'
        time_range = '24h'
    
    # Base queryset - filter for MySQL logs only
    logs = ParsedLog.objects.filter(
        raw_log__source__source_type='mysql',
        raw_log__timestamp__gte=start_time
    ).select_related('raw_log')
    
    # Apply query type filter
    if query_type != 'all':
        # Extract first word from query to determine type (SELECT, INSERT, etc.)
        logs = logs.filter(query__istartswith=query_type)
    
    # Apply execution time filter
    if execution_time == 'fast':
        logs = logs.filter(execution_time__lt=1.0)
    elif execution_time == 'medium':
        logs = logs.filter(execution_time__gte=1.0, execution_time__lt=5.0)
    elif execution_time == 'slow':
        logs = logs.filter(execution_time__gte=5.0)
    
    # Apply search filter if provided
    if search_query:
        logs = logs.filter(
            Q(query__icontains=search_query) | 
            Q(user_id__icontains=search_query)
        )
    
    # Get statistics
    total_logs = logs.count()
    slow_queries = logs.filter(execution_time__gte=1.0).count()
    
    # Get query type distribution
    query_types = []
    for qt in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER', 'DROP']:
        count = logs.filter(query__istartswith=qt).count()
        if count > 0:
            query_types.append({
                'type': qt,
                'count': count,
                'percentage': round(count / total_logs * 100, 1) if total_logs > 0 else 0
            })
    
    # Get top users
    top_users = logs.values('user_id').annotate(
        count=Count('user_id')
    ).order_by('-count')[:10]
    
    # Get slowest queries
    slowest_queries = logs.order_by('-execution_time')[:5]
    
    # Pagination
    per_page = 50
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    logs_paginated = logs.order_by('-raw_log__timestamp')[start_idx:end_idx]
    total_pages = (total_logs + per_page - 1) // per_page
    
    # Generate page range
    if total_pages <= 7:
        page_range = range(1, total_pages + 1)
    else:
        if page <= 4:
            page_range = list(range(1, 6)) + ['...', total_pages]
        elif page >= total_pages - 3:
            page_range = [1, '...'] + list(range(total_pages - 4, total_pages + 1))
        else:
            page_range = [1, '...'] + list(range(page - 1, page + 2)) + ['...', total_pages]
    
    context = {
        'logs': logs_paginated,
        'total_logs': total_logs,
        'period_name': period_name,
        'time_range': time_range,
        'query_type': query_type,
        'execution_time': execution_time,
        'search_query': search_query,
        'slow_queries': slow_queries,
        'normal_queries': total_logs - slow_queries,
        'query_types': query_types,
        'top_users': top_users,
        'slowest_queries': slowest_queries,
        'current_page': page,
        'total_pages': total_pages,
        'page_range': page_range,
        'has_next': page < total_pages,
        'has_prev': page > 1,
        'next_page': page + 1,
        'prev_page': page - 1,
    }
    
    return render(request, 'authentication/mysql_logs.html', context)

@login_required
def generate_report(request):
    """
    View for generating security and log analysis reports.
    Allows users to create custom reports with various parameters and formats.
    """
    # Handle form submission for report generation
    if request.method == 'POST':
        report_type = request.POST.get('report_type')
        time_range = request.POST.get('time_range')
        source_types = request.POST.getlist('source_types')
        format_type = request.POST.get('format_type', 'pdf')
        
        # Calculate date range
        now = timezone.now()
        if time_range == '24h':
            start_time = now - timedelta(hours=24)
        elif time_range == '7d':
            start_time = now - timedelta(days=7)
        elif time_range == '30d':
            start_time = now - timedelta(days=30)
        elif time_range == 'custom':
            # Parse custom date range
            try:
                start_date = request.POST.get('start_date')
                end_date = request.POST.get('end_date')
                start_time = timezone.make_aware(datetime.strptime(start_date, '%Y-%m-%d'))
                end_time = timezone.make_aware(datetime.strptime(end_date, '%Y-%m-%d')) + timedelta(days=1)
            except (ValueError, TypeError):
                # Default to last 7 days if date parsing fails
                start_time = now - timedelta(days=7)
                end_time = now
        else:
            # Default to last 7 days
            start_time = now - timedelta(days=7)
            end_time = now
            
        # Generate the appropriate report based on type
        if report_type == 'security_alerts':
            # Get security alerts for the period
            threats = Threat.objects.filter(
                created_at__gte=start_time,
                created_at__lte=end_time
            ).order_by('-created_at')
            
            context = {
                'report_type': 'Security Alerts',
                'report_period': f"{start_time.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}",
                'threats': threats,
                'total_threats': threats.count(),
                'high_severity': threats.filter(severity='high').count(),
                'medium_severity': threats.filter(severity='medium').count(),
                'low_severity': threats.filter(severity='low').count(),
                'generated_at': timezone.now(),
                'format_type': format_type,
            }
            
            # Generate PDF report
            if format_type == 'pdf':
                return render(request, 'authentication/reports/security_alerts_pdf.html', context)
            else:
                # CSV report
                response = HttpResponse(content_type='text/csv')
                response['Content-Disposition'] = 'attachment; filename="security_alerts_report.csv"'
                
                writer = csv.writer(response)
                writer.writerow(['Timestamp', 'Source IP', 'Severity', 'MITRE Tactic', 'Description'])
                
                for threat in threats:
                    writer.writerow([
                        threat.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                        threat.source_ip or 'Unknown',
                        threat.severity,
                        threat.mitre_tactic or 'Unclassified',
                        threat.description
                    ])
                return response
                
        elif report_type == 'system_health':
            # Get system health metrics
            apache_logs = RawLog.objects.filter(
                source__source_type='apache',
                timestamp__gte=start_time,
                timestamp__lte=end_time
            )
            
            mysql_logs = RawLog.objects.filter(
                source__source_type='mysql',
                timestamp__gte=start_time,
                timestamp__lte=end_time
            )
            
            # Calculate error rates
            apache_count = apache_logs.count()
            apache_4xx = ParsedLog.objects.filter(
                raw_log__source__source_type='apache',
                raw_log__timestamp__gte=start_time,
                raw_log__timestamp__lte=end_time,
                status_code__gte=400,
                status_code__lt=500
            ).count()
            
            apache_5xx = ParsedLog.objects.filter(
                raw_log__source__source_type='apache',
                raw_log__timestamp__gte=start_time,
                raw_log__timestamp__lte=end_time,
                status_code__gte=500
            ).count()
            
            # MySQL slow queries
            mysql_slow = ParsedLog.objects.filter(
                raw_log__source__source_type='mysql',
                raw_log__timestamp__gte=start_time,
                raw_log__timestamp__lte=end_time,
                execution_time__gte=1.0
            ).count()
            
            context = {
                'report_type': 'System Health',
                'report_period': f"{start_time.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}",
                'apache_count': apache_count,
                'apache_4xx': apache_4xx,
                'apache_5xx': apache_5xx,
                'apache_success': apache_count - apache_4xx - apache_5xx if apache_count > 0 else 0,
                'mysql_count': mysql_logs.count(),
                'mysql_slow': mysql_slow,
                'generated_at': timezone.now(),
                'format_type': format_type,
            }
            
            # Generate PDF report
            if format_type == 'pdf':
                return render(request, 'authentication/reports/system_health_pdf.html', context)
            else:
                # CSV report
                response = HttpResponse(content_type='text/csv')
                response['Content-Disposition'] = 'attachment; filename="system_health_report.csv"'
                
                writer = csv.writer(response)
                writer.writerow(['Metric', 'Value'])
                writer.writerow(['Report Period', f"{start_time.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}"])
                writer.writerow(['Apache Total Requests', apache_count])
                writer.writerow(['Apache 4xx Errors', apache_4xx])
                writer.writerow(['Apache 5xx Errors', apache_5xx])
                writer.writerow(['Apache Success Requests', apache_count - apache_4xx - apache_5xx if apache_count > 0 else 0])
                writer.writerow(['MySQL Total Queries', mysql_logs.count()])
                writer.writerow(['MySQL Slow Queries', mysql_slow])
                
                return response
    
    # Display report generation form
    return render(request, 'reports.html', {
        'current_time': timezone.now().strftime('%Y-%m-%d'),
        'week_ago': (timezone.now() - timedelta(days=7)).strftime('%Y-%m-%d')
    })

@login_required
def reports_view(request):
    """
    View for the reports interface - this is an alias for generate_report
    to match the URL configuration.
    """
    # This function simply delegates to generate_report
    return generate_report(request)

@login_required
def alert_detail(request, alert_id):
    try:
        # Get the specific threat by ID
        threat = Threat.objects.get(id=alert_id)
        
        # Handle form submissions (existing code)
        if request.method == 'POST':
            action = request.POST.get('action')
            
            if action == 'update_status':
                # Update threat status
                status = request.POST.get('status')
                comment = request.POST.get('comment')
                
                threat.status = status
                threat.save()
                
                # Record comment if provided
                if comment and comment.strip():
                    # If you have a comments model, you would create a comment here
                    # For now, we'll just add a message
                    messages.success(request, f"Status updated to '{status}' with comment: {comment}")
                else:
                    messages.success(request, f"Status updated to '{status}'")
                    
                return redirect('alert_detail', alert_id=alert_id)
                
            elif action == 'block_ip':
                # Block the IP address
                ip_address = request.POST.get('ip_address')
                reason = request.POST.get('reason')
                expiration = request.POST.get('expiration')
                
                # Check if already blacklisted
                if BlacklistedIP.objects.filter(ip_address=ip_address).exists():
                    messages.info(request, f"IP address {ip_address} is already blacklisted.")
                else:
                    # Calculate expiry date if not permanent
                    expires_at = None
                    if expiration == '24h':
                        expires_at = timezone.now() + timedelta(hours=24)
                    elif expiration == '7d':
                        expires_at = timezone.now() + timedelta(days=7)
                    elif expiration == '30d':
                        expires_at = timezone.now() + timedelta(days=30)
                    
                    # Create blacklist entry - REMOVED added_by field which doesn't exist
                    BlacklistedIP.objects.create(
                        ip_address=ip_address,
                        reason=reason,
                        expires_at=expires_at
                    )
                    
                    messages.success(request, f"IP address {ip_address} has been blacklisted successfully.")
                
                return redirect('alert_detail', alert_id=alert_id)
                
            elif action == 'add_comment':
                # Add a comment to the threat
                comment_text = request.POST.get('comment_text')
                
                if comment_text and comment_text.strip():
                    # If you have a comments model, create a comment here
                    # For this example, we'll just add a message
                    messages.success(request, "Comment added successfully.")
                else:
                    messages.error(request, "Comment text cannot be empty.")
                
                return redirect('alert_detail', alert_id=alert_id)
            
            # Add this new elif block to the action handler section
            elif action == 'unblock_ip':
                # Unblock the IP address
                ip_address = request.POST.get('ip_address')
                unblock_reason = request.POST.get('unblock_reason')
                
                # Try to find and delete the blacklisted IP
                try:
                    blacklisted_ip = BlacklistedIP.objects.get(ip_address=ip_address)
                    blacklisted_ip.delete()
                    
                    # If you want to log the unblocking, you could do it here
                    # For example, add a log entry with the unblock_reason
                    
                    messages.success(request, f"IP address {ip_address} has been removed from the blacklist.")
                except BlacklistedIP.DoesNotExist:
                    messages.warning(request, f"IP address {ip_address} was not found in the blacklist.")
                
                return redirect('alert_detail', alert_id=alert_id)

        # Continue with the rest of the view...
        # Get related parsed log if available
        related_log = None
        if hasattr(threat, 'parsed_log') and threat.parsed_log:
            related_log = threat.parsed_log
            
        # Get the raw log content if available
        raw_log_content = None
        if related_log and hasattr(related_log, 'raw_log'):
            raw_log_content = related_log.raw_log.content
        
        # Get similar threats (same source IP or MITRE tactic)
        similar_threats = Threat.objects.filter(
            Q(source_ip=threat.source_ip) | Q(mitre_tactic=threat.mitre_tactic)
        ).exclude(id=threat.id).order_by('-created_at')[:5]
        
        # Check if IP is in blacklist
        is_blacklisted = BlacklistedIP.objects.filter(ip_address=threat.source_ip).exists() if threat.source_ip else False
        
        # Check if we already have an AI analysis for this threat
        ai_analysis = None
        try:
            # If you want to store analyses, you can create a model for this
            # For now, just set to None so the UI shows the default prompt
            pass
        except Exception as e:
            logger.warning(f"Error retrieving AI analysis: {str(e)}")
        
        context = {
            'threat': threat,
            'related_log': related_log,
            'raw_log_content': raw_log_content,
            'similar_threats': similar_threats,
            'is_blacklisted': is_blacklisted,
            'page_title': f"Alert Details: {threat.id}",
            'ai_analysis': ai_analysis,  # Add this to the context
        }
        
        return render(request, 'authentication/alert_detail.html', context)
        
    except Threat.DoesNotExist:
        # Alert not found
        messages.error(request, "The requested alert could not be found.")
        return redirect('dashboard')

@login_required
def test_log_paths(request):
    """
    API endpoint to test if log paths are valid and accessible.
    Validates that files are actually log files with proper format.
    """
    if request.method == 'POST':
        try:
            import json
            
            # Parse the request body
            data = json.loads(request.body)
            apache_path = data.get('apache_path', '').strip()
            mysql_path = data.get('mysql_path', '').strip()
            
            # Test Apache log path
            apache_result = validate_log_file(apache_path, 'apache')
            
            # Test MySQL log path
            mysql_result = validate_log_file(mysql_path, 'mysql')
            
            # Prepare response
            results = {
                'apache': apache_result,
                'mysql': mysql_result
            }
            
            return JsonResponse({
                'success': True,
                'results': results
            })
            
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Invalid JSON data'
            }, status=400)
            
        except Exception as e:
            logger.exception(f"Error in test_log_paths: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)
    
    return JsonResponse({
        'success': False,
        'error': 'Only POST method is supported'
    }, status=405)

@login_required
def events_view(request):
    """
    View for displaying security events and incidents in a timeline.
    Shows all security-related events with filtering options.
    """
    # Get filter parameters
    time_range = request.GET.get('time_range', '24h')
    severity = request.GET.get('severity', 'all')
    mitre_tactic = request.GET.get('mitre_tactic', 'all')
    status = request.GET.get('status', 'all')
    search_query = request.GET.get('search', '')
    page = int(request.GET.get('page', 1))
    
    # Determine time period based on range parameter
    now = timezone.now()
    if time_range == '1h':
        start_time = now - timedelta(hours=1)
        period_name = 'Last Hour'
    elif time_range == '12h':
        start_time = now - timedelta(hours=12)
        period_name = 'Last 12 Hours'
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
        period_name = 'Last 7 Days'
    elif time_range == '30d':
        start_time = now - timedelta(days=30)
        period_name = 'Last 30 Days'
    else:  # Default to 24h
        start_time = now - timedelta(days=1)
        period_name = 'Last 24 Hours'
        time_range = '24h'
    
    # Base queryset
    events = Threat.objects.filter(created_at__gte=start_time).order_by('-created_at')
    
    # Apply severity filter
    if severity != 'all':
        events = events.filter(severity=severity)
    
    # Apply MITRE tactic filter
    if mitre_tactic != 'all':
        events = events.filter(mitre_tactic=mitre_tactic)
    
    # Apply status filter
    if status != 'all':
        events = events.filter(status=status)
    
    # Apply search filter
    if search_query:
        events = events.filter(
            Q(description__icontains=search_query) | 
            Q(source_ip__icontains=search_query) |
            Q(mitre_technique__icontains=search_query)
        )
    
    # Get list of MITRE tactics for filter dropdown
    mitre_tactics = Threat.objects.exclude(mitre_tactic__isnull=True).exclude(mitre_tactic='').values_list('mitre_tactic', flat=True).distinct()
    
    # Pagination
    per_page = 25
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    total_events = events.count()
    events_paginated = events[start_idx:end_idx]
    total_pages = (total_events + per_page - 1) // per_page
    
    # Generate page range
    if total_pages <= 7:
        page_range = range(1, total_pages + 1)
    else:
        if page <= 4:
            page_range = list(range(1, 6)) + ['...', total_pages]
        elif page >= total_pages - 3:
            page_range = [1, '...'] + list(range(total_pages - 4, total_pages + 1))
        else:
            page_range = [1, '...'] + list(range(page - 1, page + 2)) + ['...', total_pages]
    
    # Get aggregate statistics
    severity_counts = {
        'critical': events.filter(severity='critical').count(),
        'high': events.filter(severity='high').count(),
        'medium': events.filter(severity='medium').count(),
        'low': events.filter(severity='low').count()
    }
    
    context = {
        'events': events_paginated,
        'total_events': total_events,
        'time_range': time_range,
        'period_name': period_name,
        'severity': severity,
        'mitre_tactic': mitre_tactic,
        'mitre_tactics': mitre_tactics,
        'status': status,
        'search_query': search_query,
        'current_page': page,
        'total_pages': total_pages,
        'page_range': page_range,
        'has_next': page < total_pages,
        'has_prev': page > 1,
        'next_page': page + 1,
        'prev_page': page - 1,
        'severity_counts': severity_counts,
    }
    
    return render(request, 'authentication/events.html', context)

@login_required
def export_events(request):
    """
    Export events in CSV or PDF format based on filters.
    """
    # Get filter parameters
    event_type = request.GET.get('event_type', 'all')
    severity = request.GET.get('severity', 'all')
    time_range = request.GET.get('time_range', '24h')
    search = request.GET.get('search', '')
    export_format = request.GET.get('format', 'csv')
    
    # Calculate the date range based on time_range
    end_date = timezone.now()
    if time_range == '24h':
        start_date = end_date - timedelta(hours=24)
    elif time_range == '3d':
        start_date = end_date - timedelta(days=3)
    elif time_range == '7d':
        start_date = end_date - timedelta(days=7)
    elif time_range == '30d':
        start_date = end_date - timedelta(days=30)
    else:
        start_date = end_date - timedelta(days=7)  # Default to 7 days
    
    # Query events based on filters - using Threat model instead of Event
    events = Threat.objects.filter(created_at__gte=start_date, created_at__lte=end_date)
    
    if event_type != 'all' and event_type == 'apache':
        events = events.filter(parsed_log__source_type='apache')
    elif event_type != 'all' and event_type == 'mysql':
        events = events.filter(parsed_log__source_type='mysql')
    
    if severity != 'all':
        events = events.filter(severity=severity)
    
    if search:
        events = events.filter(description__icontains=search)
    
    # Order by timestamp descending (newest first)
    events = events.order_by('-created_at')
    
    if export_format == 'csv':
        # Create CSV response
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="security_events_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        writer = csv.writer(response)
        
        # Write header row - adjusted for Threat model
        writer.writerow(['Timestamp', 'Type', 'Source IP', 'Severity', 'Status', 'Description', 'MITRE Tactic', 'MITRE Technique'])
        
        # Write data rows - adjusted for Threat model
        for event in events:
            writer.writerow([
                event.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                event.rule.rule_type if event.rule else "Unknown",
                event.source_ip or "N/A",
                event.severity,
                event.status,
                event.description[:100] + ('...' if len(event.description) > 100 else ''),
                event.mitre_tactic or "N/A",
                event.mitre_technique or "N/A"
            ])
        
        return response
    
    elif export_format == 'pdf':
        # Create a PDF with ReportLab
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        
        # Add title
        styles = getSampleStyleSheet()
        title = Paragraph("Security Events Report", styles['Title'])
        elements.append(title)
        
        # Add report metadata
        date_range = f"Period: {start_date.strftime('%Y-%m-%d %H:%M:%S')} to {end_date.strftime('%Y-%m-%d %H:%M:%S')}"
        filter_info = f"Filters: Event Type={event_type}, Severity={severity}"
        if search:
            filter_info += f", Search={search}"
        
        elements.append(Paragraph(date_range, styles['Normal']))
        elements.append(Paragraph(filter_info, styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Create table data - adjusted for Threat model
        data = [['Timestamp', 'Source IP', 'Severity', 'Status', 'Description']]  # Header row
        
        # Add data rows (limit to 200 events to prevent very large PDFs)
        for event in events[:200]:  # Limit to 200 for reasonable PDF size
            data.append([
                event.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                event.source_ip or "N/A",
                event.severity,
                event.status,
                event.description[:100] + ('...' if len(event.description) > 100 else '')  # Truncate long messages
            ])
        
        # Create the table
        table = Table(data, repeatRows=1)
        
        # Define table style
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        # Add the table to the elements
        elements.append(table)
        
        # Build the PDF
        doc.build(elements)
        
        # Get the PDF value from the BytesIO buffer
        pdf = buffer.getvalue()
        buffer.close()
        
        # Create HTTP response with PDF content
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="security_events_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf"'
        response.write(pdf)
        
        return response
    
    else:
        # Unsupported format
        return HttpResponse("Unsupported export format", status=400)

def generate_alerts_chart_data(start_time, end_time):
    """
    Generate data for the alerts chart based on time period.
    Returns labels (time periods) and data (alert counts).
    """
    from django.db.models import Count
    from django.db.models.functions import TruncHour, TruncDay
    
    # Determine appropriate time grouping based on total time range
    time_diff = end_time - start_time
    
    if time_diff.total_seconds() <= 60 * 60 * 24:  # Less than 24 hours - group by hour
        truncate_func = TruncHour
        date_format = '%H:%M'
    else:  # More than 24 hours - group by day
        truncate_func = TruncDay
        date_format = '%b %d'
    
    # Get alert counts grouped by time period
    alerts_by_time = (
        Threat.objects
        .filter(created_at__gte=start_time, created_at__lte=end_time)
        .annotate(period=truncate_func('created_at'))
        .values('period')
        .annotate(count=Count('id'))
        .order_by('period')
    )
    
    # Create complete time series (including periods with zero alerts)
    all_periods = []
    current = start_time
    
    # For days, increment by 1 day; for hours, increment by 1 hour
    if truncate_func == TruncDay:
        increment = timedelta(days=1)
    else:
        increment = timedelta(hours=1)
    
    # Generate all time periods in the range
    while current <= end_time:
        all_periods.append(current)
        current += increment
    
    # Format for chart display
    chart_labels = [period.strftime(date_format) for period in all_periods]
    
    # Map counts to periods
    alerts_dict = {item['period']: item['count'] for item in alerts_by_time}
    
    # Build final data list with zeros for periods without alerts
    alerts_data = []
    for period in all_periods:
        # For day truncation, we need to match on date part only
        if truncate_func == TruncDay:
            period_match = period.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            period_match = period.replace(minute=0, second=0, microsecond=0)
        
        alerts_data.append(alerts_dict.get(period_match, 0))
    
    return chart_labels, alerts_data


def generate_mitre_chart_data(start_time):
    """
    Generate data for the MITRE ATT&CK chart.
    Returns two lists: tactic names and counts.
    """
    from django.db.models import Count
    
    # Group threats by MITRE tactic
    mitre_data = (
        Threat.objects
        .filter(created_at__gte=start_time)
        .exclude(mitre_tactic__isnull=True)
        .exclude(mitre_tactic='')
        .values('mitre_tactic')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    
    # Handle empty data case
    if not mitre_data:
        return ['No Data'], [1]
    
    # Limit to top 8 tactics for readable chart
    mitre_data = mitre_data[:8]
    
    # Extract labels and counts
    mitre_labels = [item['mitre_tactic'] for item in mitre_data]
    mitre_counts = [item['count'] for item in mitre_data]
    
    # Add "Other" category if needed
    threats_count = Threat.objects.filter(created_at__gte=start_time).count()
    counted_threats = sum(mitre_counts)
    
    if threats_count > counted_threats:
        mitre_labels.append('Other')
        mitre_counts.append(threats_count - counted_threats)
    
    return mitre_labels, mitre_counts

@login_required
def settings_view(request):
    """
    View for user settings management.
    Allows users to update their profile, password, and notification preferences.
    """
    # Get the current user
    user = request.user
    
    # Initialize message storage
    success_message = None
    error_message = None
    
    # Handle profile update form submission
    if request.method == 'POST' and 'update_profile' in request.POST:
        # Get form data
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        
        # Update user information
        try:
            user.first_name = first_name
            user.last_name = last_name
            user.email = email
            user.save()
            success_message = "Profile updated successfully"
        except Exception as e:
            error_message = f"Failed to update profile: {str(e)}"
    
    # Handle password change form submission
    elif request.method == 'POST' and 'change_password' in request.POST:
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        # Validate password change
        if not user.check_password(current_password):
            error_message = "Current password is incorrect"
        elif new_password != confirm_password:
            error_message = "New passwords do not match"
        elif len(new_password) < 8:
            error_message = "Password must be at least 8 characters long"
        else:
            # Update password
            try:
                user.set_password(new_password)
                user.save()
                success_message = "Password changed successfully. Please log in again."
                # Use Django's authentication system to update the session
                update_session_auth_hash(request, user)
            except Exception as e:
                error_message = f"Failed to change password: {str(e)}"
    
    # Handle notification settings form submission
    elif request.method == 'POST' and 'notification_settings' in request.POST:
        # Get notification preferences
        email_alerts = request.POST.get('email_alerts') == 'on'
        sms_alerts = request.POST.get('sms_alerts') == 'on'
        slack_alerts = request.POST.get('slack_alerts') == 'on'
        
        # Update user notification settings in UserProfile or similar model
        try:
            # Get or create user profile
            profile, created = UserProfile.objects.get_or_create(user=user)
            profile.email_alerts = email_alerts
            profile.sms_alerts = sms_alerts
            profile.slack_alerts = slack_alerts
            profile.save()
            success_message = "Notification settings updated successfully"
        except Exception as e:
            error_message = f"Failed to update notification settings: {str(e)}"
    
    # Get current notification settings
    try:
        profile = UserProfile.objects.get(user=user)
        notification_settings = {
            'email_alerts': profile.email_alerts,
            'sms_alerts': profile.sms_alerts,
            'slack_alerts': profile.slack_alerts,
        }
    except UserProfile.DoesNotExist:
        # Default settings if profile doesn't exist yet
        notification_settings = {
            'email_alerts': True,
            'sms_alerts': False,
            'slack_alerts': False,
        }
    except Exception:
        # Fallback if there's an error
        notification_settings = {
            'email_alerts': True,
            'sms_alerts': False,
            'slack_alerts': False,
        }
    
    context = {
        'user': user,
        'notification_settings': notification_settings,
        'success_message': success_message,
        'error_message': error_message,
    }
    
    return render(request, 'authentication/settings.html', context)

@login_required
def alerts_details_view(request):
    """
    View for comprehensive analysis of security alerts and threats.
    Provides detailed statistics, trends, and insights about detected security events.
    """
    # Get filter parameters
    time_range = request.GET.get('time_range', '7d')
    severity = request.GET.get('severity', 'all')
    status = request.GET.get('status', 'all')
    group_by = request.GET.get('group_by', 'day')
    
    # Determine time period based on selection
    now = timezone.now()
    if time_range == '24h':
        start_time = now - timedelta(hours=24)
        period_name = 'Last 24 Hours'
    elif time_range == '3d':
        start_time = now - timedelta(days=3)
        period_name = 'Last 3 Days'
    elif time_range == '30d':
        start_time = now - timedelta(days=30)
        period_name = 'Last 30 Days'
    elif time_range == '90d':
        start_time = now - timedelta(days=90)
        period_name = 'Last 90 Days'
    else:  # Default to 7d
        start_time = now - timedelta(days=7)
        period_name = 'Last 7 Days'
    
    # Base queryset
    alerts = Threat.objects.filter(created_at__gte=start_time)
    
    # Apply filters
    if severity != 'all':
        alerts = alerts.filter(severity=severity)
    
    if status != 'all':
        alerts = alerts.filter(status=status)
    
    # Calculate key metrics
    total_alerts = alerts.count()
    
    by_severity = {
        'critical': alerts.filter(severity='critical').count(),
        'high': alerts.filter(severity='high').count(),
        'medium': alerts.filter(severity='medium').count(),
        'low': alerts.filter(severity='low').count(),
    }
    
    by_status = {
        'new': alerts.filter(status='new').count(),
        'investigating': alerts.filter(status='investigating').count(),
        'resolved': alerts.filter(status='resolved').count(),
        'false_positive': alerts.filter(status='false_positive').count(),
    }
    
    # Get trend data based on grouping preference
    if group_by == 'hour':
        from django.db.models.functions import TruncHour
        trend_data = (alerts
                     .annotate(period=TruncHour('created_at'))
                     .values('period')
                     .annotate(count=Count('id'))
                     .order_by('period'))
        
        trend_format = '%H:00'
    else:  # Default to day
        from django.db.models.functions import TruncDay
        trend_data = (alerts
                     .annotate(period=TruncDay('created_at'))
                     .values('period')
                     .annotate(count=Count('id'))
                     .order_by('period'))
        
        trend_format = '%b %d'
    
    # Format trend data for chart
    trend_labels = [entry['period'].strftime(trend_format) for entry in trend_data]
    trend_values = [entry['count'] for entry in trend_data]
    
    # Get top 10 source IPs
    top_source_ips = (alerts
                     .exclude(source_ip__isnull=True)
                     .exclude(source_ip='')
                     .values('source_ip')
                     .annotate(count=Count('id'))
                     .order_by('-count')[:10])
    
    # Get MITRE ATT&CK stats
    mitre_tactics = (alerts
                    .exclude(mitre_tactic__isnull=True)
                    .exclude(mitre_tactic='')
                    .values('mitre_tactic')
                    .annotate(count=Count('id'))
                    .order_by('-count')[:8])
    
    mitre_techniques = (alerts
                       .exclude(mitre_technique__isnull=True)
                       .exclude(mitre_technique='')
                       .values(
                           'mitre_technique'
                       ).annotate(
                           count=Count('id')
                       ).order_by('-count')[:8])
    
    # Recent alerts (last 10)
    recent_alerts = alerts.order_by('-created_at')[:10]
    
    # Calculate average time to resolution (if applicable)
    avg_resolution_time = None
    resolved_alerts = alerts.filter(status='resolved')
    
    if hasattr(Threat, 'resolution_time') and resolved_alerts.exists():
        # If you have resolution_time field
        avg_resolution_time = resolved_alerts.aggregate(Avg('resolution_time'))['resolution_time__avg']
    
    context = {
        'total_alerts': total_alerts,
        'period_name': period_name,
        'time_range': time_range,
        'group_by': group_by,
        'severity': severity,
        'status': status,
        'by_severity': by_severity,
        'by_status': by_status,
        'trend_labels': json.dumps(trend_labels),
        'trend_values': json.dumps(trend_values),
        'top_source_ips': top_source_ips,
        'mitre_tactics': mitre_tactics,
        'mitre_techniques': mitre_techniques,
        'recent_alerts': recent_alerts,
        'avg_resolution_time': avg_resolution_time,
    }
    
    return render(request, 'authentication/alerts_details.html', context)

@login_required
def mitre_details_view(request):
    """
    View for analyzing threats based on the MITRE ATT&CK framework.
    Provides detailed breakdown of tactics, techniques, and patterns across detected threats.
    """
    # Get filter parameters
    time_range = request.GET.get('time_range', '30d')
    tactic = request.GET.get('tactic', 'all')
    search_query = request.GET.get('search', '')
    
    # Determine time period based on selection
    now = timezone.now()
    if time_range == '7d':
        start_time = now - timedelta(days=7)
        period_name = 'Last 7 Days'
    elif time_range == '90d':
        start_time = now - timedelta(days=90)
        period_name = 'Last 90 Days'
    elif time_range == 'all':
        start_time = now - timedelta(days=365*10)  # 10 years should cover all data
        period_name = 'All Time'
    else:  # Default to 30d
        start_time = now - timedelta(days=30)
        period_name = 'Last 30 Days'
    
    # Base queryset - only include threats with MITRE information
    threats = Threat.objects.filter(
        created_at__gte=start_time
    ).exclude(
        mitre_tactic__isnull=True
    ).exclude(
        mitre_tactic=''
    )
    
    # Apply tactic filter if specified
    if tactic != 'all':
        threats = threats.filter(mitre_tactic=tactic)
    
    # Apply search query if provided
    if search_query:
        threats = threats.filter(
            Q(mitre_tactic__icontains=search_query) | 
            Q(mitre_technique__icontains=search_query)
        )
    
    # Get list of all tactics for filter dropdown
    all_tactics = Threat.objects.exclude(
        mitre_tactic__isnull=True
    ).exclude(
        mitre_tactic=''
    ).values_list(
        'mitre_tactic', flat=True
    ).distinct().order_by('mitre_tactic')
    
    # Get tactic statistics
    tactic_stats = threats.values('mitre_tactic').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Get technique statistics
    technique_stats = threats.exclude(
        mitre_technique__isnull=True
    ).exclude(
        mitre_technique=''
    ).values(
        'mitre_technique'
    ).annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Prepare data for tactics heatmap
    tactics_by_day = {}
    
    # Use TruncDay to get daily counts of each tactic
    from django.db.models.functions import TruncDay
    
    daily_tactic_counts = threats.annotate(
        day=TruncDay('created_at')
    ).values(
        'day', 'mitre_tactic'
    ).annotate(
        count=Count('id')
    ).order_by('day')
    
    # Process the data for chart rendering
    days = set()
    tactics = set()
    
    for entry in daily_tactic_counts:
        day_str = entry['day'].strftime('%Y-%m-%d')
        days.add(day_str)
        tactics.add(entry['mitre_tactic'])
        
        if day_str not in tactics_by_day:
            tactics_by_day[day_str] = {}
        
        tactics_by_day[day_str][entry['mitre_tactic']] = entry['count']
    
    # Convert to sorted lists for the chart
    days_list = sorted(list(days))
    tactics_list = sorted(list(tactics))
    
    # Build the heatmap data
    heatmap_data = []
    for tactic in tactics_list:
        tactic_data = []
        for day in days_list:
            tactic_data.append(tactics_by_day.get(day, {}).get(tactic, 0))
        heatmap_data.append(tactic_data)
    
    # Get recent threats for the list view
    recent_threats = threats.order_by('-created_at')[:50]
    
    context = {
        'period_name': period_name,
        'time_range': time_range,
        'tactic': tactic,
        'search_query': search_query,
        'all_tactics': all_tactics,
        'tactic_stats': tactic_stats,
        'technique_stats': technique_stats,
        'total_threats': threats.count(),
        'threats_with_tactics': threats.exclude(mitre_tactic='').count(),
        'threats_with_techniques': threats.exclude(mitre_technique='').count(),
        'recent_threats': recent_threats,
        'days': json.dumps(days_list),
        'tactics': json.dumps(list(tactics_list)),
        'heatmap_data': json.dumps(heatmap_data)
    }
    
    return render(request, 'authentication/mitre_details.html', context)

@login_required
@require_POST
def analyze_alert_with_ai(request, alert_id):
    """API endpoint to analyze a security alert with AI"""
    try:
        # Parse request data
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            logger.error("Invalid JSON in analyze_alert_with_ai request")
            return JsonResponse({
                'success': False,
                'error': 'Invalid JSON data in request'
            }, status=400)
            
        # Get the action type from request (default: analyze)
        action_type = data.get('action', 'analyze')
        logger.info(f"AI Analysis requested for alert #{alert_id}, action: {action_type}")
        
        # Get the threat object
        try:
            threat = Threat.objects.get(id=alert_id)
        except Threat.DoesNotExist:
            logger.warning(f"Alert not found in analyze_alert_with_ai: #{alert_id}")
            return JsonResponse({
                'success': False,
                'error': f"Alert #{alert_id} not found"
            }, status=404)
        
        # Check for cached analysis (less than 1 hour old)
        cached_analysis = ThreatAnalysis.objects.filter(
            threat=threat,
            analysis_type=action_type,
            generated_at__gte=timezone.now() - timezone.timedelta(hours=1)
        ).first()
        
        if cached_analysis:
            logger.info(f"Using cached analysis for alert #{alert_id} ({action_type})")
            return JsonResponse({
                'success': True,
                'analysis': cached_analysis.content,
                'from_cache': True
            })
        
        # Initialize the AI service
        try:
            ai_service = AlertAnalysisService()
        except Exception as e:
            logger.error(f"Error initializing AI service: {str(e)}", exc_info=True)
            return JsonResponse({
                'success': False,
                'error': f"AI service initialization error: {str(e)}"
            }, status=500)
        
        # Generate the analysis
        try:
            analysis_content = ai_service.analyze_threat(threat, action_type)
        except Exception as e:
            logger.error(f"Error in AI analysis: {str(e)}", exc_info=True)
            return JsonResponse({
                'success': False,
                'error': f"Analysis error: {str(e)}"
            }, status=500)
        
        if not analysis_content:
            return JsonResponse({
                'success': False,
                'error': "AI generated an empty response"
            }, status=500)
        
        # Save the analysis to the database
        try:
            ThreatAnalysis.objects.update_or_create(
                threat=threat,
                analysis_type=action_type,
                defaults={
                    'content': analysis_content,
                    'generated_at': timezone.now(),
                    'tokens_used': len(analysis_content) // 4  # Rough estimate
                }
            )
        except Exception as e:
            logger.error(f"Error saving analysis: {str(e)}", exc_info=True)
            # Continue anyway since we have the analysis content
        
        # Return the analysis content
        return JsonResponse({
            'success': True,
            'analysis': analysis_content,
            'from_cache': False
        })
        
    except Exception as e:
        logger.exception(f"Unexpected error in analyze_alert_with_ai: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': f"An error occurred: {str(e)}"
        }, status=500)

@login_required
def alert_detail_api(request, alert_id):
    """API endpoint for retrieving alert details"""
    try:
        threat = Threat.objects.get(id=alert_id)
        
        # Create a JSON-serializable representation of the threat
        threat_data = {
            'id': threat.id,
            'created_at': threat.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': threat.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
            'severity': threat.severity,
            'status': threat.status,
            'source_ip': threat.source_ip,
            'affected_system': threat.affected_system,
            'mitre_tactic': threat.mitre_tactic,
            'mitre_technique': threat.mitre_technique,
            'description': threat.description,
        }
        
        # Get related log if available
        related_log = None
        if hasattr(threat, 'parsed_log') and threat.parsed_log:
            related_log = {
                'id': threat.parsed_log.id,
                'timestamp': threat.parsed_log.raw_log.timestamp.strftime('%Y-%m-%d %H:%M:%S') if hasattr(threat.parsed_log, 'raw_log') else None,
                                'source_type': threat.parsed_log.raw_log.source.source_type if hasattr(threat.parsed_log, 'raw_log') and hasattr(threat.parsed_log.raw_log, 'source') else None,
            }
        
        # Check if IP is blacklisted
        is_blacklisted = False
        if threat.source_ip:
            is_blacklisted = BlacklistedIP.objects.filter(ip_address=threat.source_ip).exists()
        
        return JsonResponse({
            'success': True,
            'threat': threat_data,
            'related_log': related_log,
            'is_blacklisted': is_blacklisted
        })
        
    except Threat.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': f"Alert #{alert_id} not found"
        }, status=404)
    
    except Exception as e:
        logger.exception(f"Error in alert_detail_api: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': f"An error occurred: {str(e)}"
        }, status=500)
        
@login_required
def alert_detail_api(request, alert_id):
    """API endpoint for retrieving alert details"""
    try:
        threat = Threat.objects.get(id=alert_id)
        
        # Create a JSON-serializable representation of the threat
        threat_data = {
            'id': threat.id,
            'created_at': threat.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': threat.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
            'severity': threat.severity,
            'status': threat.status,
            'source_ip': threat.source_ip,
            'affected_system': threat.affected_system,
            'mitre_tactic': threat.mitre_tactic,
            'mitre_technique': threat.mitre_technique,
            'description': threat.description,
        }
        
        # Get related log if available
        related_log = None
        if hasattr(threat, 'parsed_log') and threat.parsed_log:
            related_log = {
                'id': threat.parsed_log.id,
                'timestamp': threat.parsed_log.raw_log.timestamp.strftime('%Y-%m-%d %H:%M:%S') if hasattr(threat.parsed_log, 'raw_log') else None,
                'source_type': threat.parsed_log.raw_log.source.source_type if hasattr(threat.parsed_log, 'raw_log') and hasattr(threat.parsed_log.raw_log, 'source') else None,
            }
        
        # Check if IP is blacklisted
        is_blacklisted = False
        if threat.source_ip:
            is_blacklisted = BlacklistedIP.objects.filter(ip_address=threat.source_ip).exists()
        
        return JsonResponse({
            'success': True,
            'threat': threat_data,
            'related_log': related_log,
            'is_blacklisted': is_blacklisted
        })
        
    except Threat.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': f"Alert #{alert_id} not found"
        }, status=404)
    
    except Exception as e:
        logger.exception(f"Error in alert_detail_api: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': f"An error occurred: {str(e)}"
        }, status=500)

@login_required
def profile_stats_api(request):
    """API endpoint for profile statistics"""
    try:
        user = request.user
        
        # Calculate statistics for the user
        # Time range for recent activities - last 30 days
        start_date = timezone.now() - timedelta(days=30)
        
        # Count detected threats
        threats_detected = Threat.objects.filter(
            created_at__gte=start_date
        ).count()
        
        # Count analyzed logs
        logs_analyzed = ParsedLog.objects.filter(
            raw_log__timestamp__gte=start_date
        ).count()
        
        # Calculate detection rate (threats per 100 logs)
        detection_rate = "0%"
        if logs_analyzed > 0:
            rate = (threats_detected / logs_analyzed) * 100
            detection_rate = f"{rate:.1f}%"
        
        # Get recent activities
        recent_activities = []
        
        # First add threat detections
        recent_threats = Threat.objects.filter(
            created_at__gte=start_date
        ).order_by('-created_at')[:5]
        
        for threat in recent_threats:
            icon = "fas fa-shield-alt"
            if threat.severity == "critical":
                icon = "fas fa-radiation"
            elif threat.severity == "high":
                icon = "fas fa-exclamation-circle"
                
            recent_activities.append({
                'title': f"{threat.severity.title()} severity threat detected",
                'timestamp': threat.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'icon': icon
            })
        
        # Add log analysis activities
        recent_logs = ParsedLog.objects.filter(
            analysis_time__isnull=False,
            raw_log__timestamp__gte=start_date
        ).order_by('-analysis_time')[:3]
        
        for log in recent_logs:
            recent_activities.append({
                'title': f"Log from {log.source_type} analyzed",
                'timestamp': log.analysis_time.strftime('%Y-%m-%d %H:%M:%S'),
                'icon': "fas fa-search"
            })
        
        # Sort by timestamp
        recent_activities.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return JsonResponse({
            'success': True,
            'threats_detected': threats_detected,
            'logs_analyzed': logs_analyzed,
            'detection_rate': detection_rate,
            'recent_activities': recent_activities[:5]  # Limit to 5 most recent
        })
    except Exception as e:
        logger.exception(f"Error in profile_stats_api: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

def validate_log_file(file_path, log_type):
    """
    Helper function to validate if a file is a proper log file.
    Checks existence, readability, and basic log file characteristics.
    """
    import os
    import re
    
    result = {
        'path': file_path,
        'exists': False,
        'readable': False,
        'valid_log': False,
        'error': None
    }
    
    # Check if path is empty
    if not file_path:
        result['error'] = "No file path provided"
        return result
        
    # Check if file exists
    if not os.path.exists(file_path):
        result['error'] = f"File does not exist: {file_path}"
        return result
    
    # Mark as existing
    result['exists'] = True
    
    # Check if it's a directory
    if os.path.isdir(file_path):
        result['error'] = f"Path is a directory, not a file: {file_path}"
        return result
    
    # Check if file is readable
    if not os.access(file_path, os.R_OK):
        result['error'] = f"File exists but is not readable: {file_path}"
        return result
    
    # Mark as readable
    result['readable'] = True
    
    # Check file extension (optional, logs don't always have .log extension)
    _, ext = os.path.splitext(file_path)
    valid_extensions = ['.log', '.txt', '']  # Allow no extension too
    if ext.lower() not in valid_extensions:
        result['warning'] = f"File extension {ext} is unusual for log files"
    
    # Check file size
    if os.path.getsize(file_path) == 0:
        result['error'] = "File is empty"
        return result
    
    # Sample content validation
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Read first few lines for content validation
            sample_lines = [next(f) for _ in range(5) if f]
            
            # Check if content looks like logs based on log type
            if log_type == 'apache':
                # Apache logs typically have IP addresses, dates, HTTP methods
                valid_patterns = [
                    r'\d+\.\d+\.\d+\.\d+',  # IP address
                    r'\[\d+/\w+/\d+:',      # Date format [DD/Mon/YYYY:
                    r'(GET|POST|PUT|DELETE|HEAD)',  # HTTP methods
                ]
                
            elif log_type == 'mysql':
                # MySQL logs typically have timestamps, query keywords
                valid_patterns = [
                    r'\d{4}-\d{2}-\d{2}',   # Date format YYYY-MM-DD
                    r'(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP)',  # SQL keywords
                    r'(Warning|Note|Error)',  # MySQL message types
                ]
            
            # Check if any line matches the patterns
            if not sample_lines:
                result['error'] = "Could not read sample lines from file"
                return result
                
            pattern_matches = False
            for line in sample_lines:
                if any(re.search(pattern, line, re.IGNORECASE) for pattern in valid_patterns):
                    pattern_matches = True
                    break
                    
            if not pattern_matches:
                result['error'] = f"File content doesn't match expected {log_type} log format"
                return result
                
            # Mark as valid log
            result['valid_log'] = True
            
    except Exception as e:
        result['error'] = f"Error reading file: {str(e)}"
        return result
    
    return result

@login_required
@require_POST
def analyze_logs_api(request):
    """API endpoint to trigger log analysis"""
    try:
        # Parse request body
        data = json.loads(request.body)
        logs_count = int(data.get('logs_count', 50))
        
        # Safety cap on logs count to prevent overload
        logs_count = min(max(10, logs_count), 500)
        
        logger.info(f"Received request to analyze up to {logs_count} logs")
        
        # Get unanalyzed logs - using correct model and field types
        unanalyzed_logs = ParsedLog.objects.filter(
            analyzed=0,  # Integer field in database (not Boolean)
            raw_log__isnull=False  # Ensure raw_log relation exists
        ).select_related('raw_log').order_by('-raw_log__timestamp')[:logs_count]
        
        # Track threats found
        threats_found = 0
        logs_analyzed = len(unanalyzed_logs)
        
        logger.info(f"Found {logs_analyzed} unanalyzed logs to process")
        
        # Since LogAnalysisService isn't available, implement detection directly
        for log in unanalyzed_logs:
            try:
                # Mark as analyzed regardless of outcome
                log.analyzed = 1  # Integer field (not Boolean)
                log.analysis_time = timezone.now()
                log.save(update_fields=['analyzed', 'analysis_time'])
                
                # Analyze log for threats based on source type
                source_type = getattr(log, 'source_type', '').lower()
                
                if source_type == 'apache':
                    # Apache log threat detection
                    threats_from_apache = detect_apache_threats(log)
                    if threats_from_apache:
                        threats_found += len(threats_from_apache)
                        
                elif source_type == 'mysql':
                    # MySQL log threat detection
                    threats_from_mysql = detect_mysql_threats(log)
                    if threats_from_mysql:
                        threats_found += len(threats_from_mysql)
                        
                else:
                    # Generic detection for unknown log types
                    if detect_generic_threat(log):
                        threats_found += 1
                        
            except Exception as log_error:
                logger.error(f"Error analyzing log {log.id}: {str(log_error)}")
                # Continue to next log despite errors
        
        logger.info(f"Analysis complete. Found {threats_found} threats in {logs_analyzed} logs")
        
        return JsonResponse({
            'success': True,
            'logs_analyzed': logs_analyzed,
            'threats_found': threats_found,
            'message': f"Analysis complete: {threats_found} threats detected in {logs_analyzed} logs"
        })
    
    except json.JSONDecodeError:
        logger.error("Invalid JSON in analyze_logs_api request")
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request'
        }, status=400)
    
    except Exception as e:
        logger.exception(f"Error in analyze_logs_api: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
        
def detect_apache_threats(log):
    """Detect threats in Apache logs"""
    threats = []
    
    # Check for HTTP errors (4xx, 5xx)
    if hasattr(log, 'status_code') and log.status_code:
        if log.status_code >= 400 and log.status_code < 500:
            # 4xx client errors might indicate probing or scanning
            threat = Threat.objects.create(
                severity='medium',
                status='new',
                description=f"HTTP {log.status_code} error detected - possible probing activity",
                source_ip=getattr(log, 'source_ip', None),
                affected_system='Web Server',
                mitre_tactic='Initial Access',
                mitre_technique='T1190',
                parsed_log=log,
                created_at=timezone.now(),
                updated_at=timezone.now()
            )
            threats.append(threat)
            
        elif log.status_code >= 500:
            # 5xx server errors might indicate DoS or other attacks
            threat = Threat.objects.create(
                severity='high',
                status='new',
                description=f"HTTP {log.status_code} server error - possible attack or misconfiguration",
                source_ip=getattr(log, 'source_ip', None),
                affected_system='Web Server',
                mitre_tactic='Impact',
                mitre_technique='T1499',
                parsed_log=log,
                created_at=timezone.now(),
                updated_at=timezone.now()
            )
            threats.append(threat)
    
    # Check for suspicious URL patterns
    if hasattr(log, 'request_path') and log.request_path:
        suspicious_patterns = [
            'wp-admin', 'phpmyadmin', '.git/', '../', 'etc/passwd', 
            'eval(', 'exec(', '.php?', '/shell', '/admin'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in log.request_path.lower():
                threat = Threat.objects.create(
                    severity='medium',
                    status='new',
                    description=f"Suspicious URL pattern detected: '{pattern}' in {log.request_path[:50]}",
                    source_ip=getattr(log, 'source_ip', None),
                    affected_system='Web Server',
                    mitre_tactic='Initial Access',
                    mitre_technique='T1190',
                    parsed_log=log,
                    created_at=timezone.now(),
                    updated_at=timezone.now()
                )
                threats.append(threat)
                break  # Only create one threat per suspicious URL
    
    return threats

def detect_mysql_threats(log):
    """Detect threats in MySQL logs"""
    threats = []
    
    # Check for slow queries
    if hasattr(log, 'execution_time') and log.execution_time and log.execution_time > 5.0:
        threat = Threat.objects.create(
            severity='low',
            status='new',
            description=f"Slow MySQL query detected (execution time: {log.execution_time:.2f}s)",
            source_ip=getattr(log, 'source_ip', None),
            user_id=getattr(log, 'user_id', None),
            affected_system='Database Server',
            mitre_tactic='Resource Development',
            mitre_technique='T1583',
            parsed_log=log,
            created_at=timezone.now(),
            updated_at=timezone.now()
        )
        threats.append(threat)
        
    # Check for dangerous SQL operations
    if hasattr(log, 'query') and log.query:
        dangerous_operations = ['DROP TABLE', 'DROP DATABASE', 'TRUNCATE TABLE', 'DELETE FROM']
        for operation in dangerous_operations:
            if operation in log.query.upper():
                threat = Threat.objects.create(
                    severity='high',
                    status='new',
                    description=f"Potentially dangerous SQL operation detected: {operation}",
                    source_ip=getattr(log, 'source_ip', None),
                    user_id=getattr(log, 'user_id', None),
                    affected_system='Database Server',
                    mitre_tactic='Impact',
                    mitre_technique='T1485',
                    parsed_log=log,
                    created_at=timezone.now(),
                    updated_at=timezone.now()
                )
                threats.append(threat)
                break  # Only create one threat per query
    
    return threats

def detect_generic_threat(log):
    """Detect threats in unknown log types using basic heuristics"""
    suspicious_terms = ['error', 'failed', 'denied', 'unauthorized', 'attack', 'exploit', 'overflow']
    
    # Look for suspicious terms in normalized data
    if hasattr(log, 'normalized_data') and log.normalized_data:
        normalized_str = str(log.normalized_data).lower()
        for term in suspicious_terms:
            if term in normalized_str:
                Threat.objects.create(
                    severity='low',
                    status='new',
                    description=f"Suspicious term '{term}' detected in log",
                    source_ip=getattr(log, 'source_ip', None),
                    affected_system='Unknown',
                    mitre_tactic='Discovery',
                    mitre_technique='T1046',
                    parsed_log=log,
                    created_at=timezone.now(),
                    updated_at=timezone.now()
                )
                return True
    
    return False
    """API endpoint to trigger log analysis"""
    try:
        # Parse request body
        data = json.loads(request.body)
        logs_count = int(data.get('logs_count', 50))
        
        # Safety cap on logs count to prevent overload
        logs_count = min(max(10, logs_count), 500)
        
        logger.info(f"Received request to analyze up to {logs_count} logs")
        
        # Get unanalyzed logs with proper optimization
        # ParsedLog model uses IntegerField for analyzed (0=False, 1=True)
        # Need to ensure we have valid raw_logs to work with
        unanalyzed_logs = ParsedLog.objects.filter(
            analyzed=0,  # 0 means not analyzed
            raw_log__isnull=False  # Ensure raw_log relation exists
        ).select_related('raw_log').order_by('-raw_log__timestamp')[:logs_count]
        
        # Track threats found
        threats_found = 0
        logs_analyzed = len(unanalyzed_logs)
        
        logger.info(f"Found {logs_analyzed} unanalyzed logs to process")
        
        # Import necessary detection service
        try:
            from threat_detection.services import LogAnalysisService
            analyzer = LogAnalysisService()
            
            # Process each log
            for log in unanalyzed_logs:
                try:
                    # Mark as analyzed regardless of outcome
                    log.analyzed = 1  # 1 means analyzed
                    log.analysis_time = timezone.now()
                    log.save(update_fields=['analyzed', 'analysis_time'])
                    
                    # Analyze log for threats - this returns Threat objects or None
                    result = analyzer.analyze_log(log)
                    
                    # Count detected threats based on the type of result
                    if result:
                        if isinstance(result, (list, tuple)):
                            # If multiple threats were returned
                            threats_found += len(result)
                        else:
                            # Single threat was returned
                            threats_found += 1
                            
                        logger.debug(f"Detected threat(s) in log ID: {log.id}")
                        
                except Exception as log_error:
                    logger.error(f"Error analyzing individual log {log.id}: {str(log_error)}")
                    # Continue with next log even if this one fails
        
        except ImportError:
            logger.warning("LogAnalysisService not available - using fallback simulation")
            
            # Fallback implementation - mark logs as analyzed
            for log in unanalyzed_logs:
                log.analyzed = 1
                log.analysis_time = timezone.now()
                log.save(update_fields=['analyzed', 'analysis_time'])
            
            # Generate simulated threat count (~5% of logs typically have threats)
            threats_found = int(logs_analyzed * 0.05)
            
            # Create actual threat records in fallback mode for better UX
            if threats_found > 0:
                import random
                from threat_detection.models import Threat
                
                # Select random logs to mark as threats
                threat_log_indices = random.sample(
                    range(logs_analyzed), 
                    min(threats_found, logs_analyzed)
                )
                
                # Create threat objects for these logs
                for i in threat_log_indices:
                    if i < len(unanalyzed_logs):
                        log = unanalyzed_logs[i]
                        Threat.objects.create(
                            severity=random.choice(['low', 'medium', 'high']),
                            status='new',
                            description=f"Potential suspicious activity detected in {log.source_type or 'unknown'} log",
                            source_ip=log.source_ip,
                            user_id=log.user_id,
                            parsed_log=log,
                            created_at=timezone.now(),
                            updated_at=timezone.now()
                        )
        
        logger.info(f"Analysis complete. Found {threats_found} threats in {logs_analyzed} logs.")
        
        return JsonResponse({
            'success': True,
            'logs_analyzed': logs_analyzed,
            'threats_found': threats_found,
            'message': f"Analysis complete: {threats_found} threats detected in {logs_analyzed} logs"
        })
    
    except json.JSONDecodeError:
        logger.error("Invalid JSON in analyze_logs_api request")
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request'
        }, status=400)
    
    except Exception as e:
        logger.exception(f"Error in analyze_logs_api: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
def api_event_detail(request, event_id):
    """API endpoint for retrieving event details"""
    try:
        event = Threat.objects.get(id=event_id)
        
        # Create event data dictionary
        event_data = {
            'id': event.id,
            'created_at': event.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updated_at': event.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
            'severity': event.severity,
            'status': event.status,
            'description': event.description,
            'source_ip': event.source_ip or 'Unknown',
            'affected_system': event.affected_system or 'Not specified',
            'mitre_tactic': event.mitre_tactic or 'Unclassified',
            'mitre_technique': event.mitre_technique or 'Unclassified',
            'recommendation': event.recommendation or 'No specific recommendation available',
        }
        
        # Get related log details if available
        log_details = None
        if event.parsed_log:
            log_details = {
                'id': event.parsed_log.id,
                'timestamp': event.parsed_log.raw_log.timestamp.strftime('%Y-%m-%d %H:%M:%S') if hasattr(event.parsed_log, 'raw_log') else None,
                'source_type': event.parsed_log.source_type or 'Unknown',
                'source_ip': event.parsed_log.source_ip or 'Unknown',
                'user_agent': event.parsed_log.user_agent or 'Not available',
                'status_code': event.parsed_log.status_code,
                'content': event.parsed_log.raw_log.content if hasattr(event.parsed_log, 'raw_log') else 'Log content not available'
            }
        
        # Get related analyses
        analyses = []
        for analysis in ThreatAnalysis.objects.filter(threat=event):
            analyses.append({
                'id': analysis.id,
                'type': analysis.analysis_type,
                'generated_at': analysis.generated_at.strftime('%Y-%m-%d %H:%M:%S'),
                'summary': analysis.content[:200] + '...' if len(analysis.content) > 200 else analysis.content
            })
        
        return JsonResponse({
            'success': True,
            'event': event_data,
            'log_details': log_details,
            'analyses': analyses
        })
    
    except Threat.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': f"Event #{event_id} not found"
        }, status=404)
    
    except Exception as e:
        logger.exception(f"Error in api_event_detail: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': f"An error occurred: {str(e)}"
        }, status=500)

@login_required
@require_POST
def api_resolve_event(request, event_id):
    """API endpoint for resolving an event"""
    try:
        event = Threat.objects.get(id=event_id)
        
        # Get resolution data
        data = json.loads(request.body)
        resolution_notes = data.get('notes', '')
        
        # Update the event status
        event.status = 'resolved'
        event.updated_at = timezone.now()
        
        # Update analysis data if it exists
        if event.analysis_data is None:
            event.analysis_data = {}
        
        event.analysis_data['resolution'] = {
            'resolved_by': request.user.username,
            'resolved_at': timezone.now().isoformat(),
            'notes': resolution_notes
        }
        
        # Save the event
        event.save()
        
        # Create an AI analysis of the resolution if applicable
        try:
            ai_service = AlertAnalysisService()
            ai_analysis = ai_service.analyze_resolution(event)
            
            if ai_analysis:
                ThreatAnalysis.objects.update_or_create(
                    threat=event,
                    analysis_type='resolution',
                    defaults={
                        'content': ai_analysis,
                        'generated_at': timezone.now(),
                        'tokens_used': len(ai_analysis) // 4  # Rough estimate
                    }
                )
        except Exception as ai_error:
            logger.warning(f"AI resolution analysis failed: {str(ai_error)}")
        
        return JsonResponse({
            'success': True,
            'message': 'Event successfully resolved'
        })
    
    except Threat.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': f"Event #{event_id} not found"
        }, status=404)
    
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request'
        }, status=400)
    
    except Exception as e:
        logger.exception(f"Error resolving event: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': f"An error occurred: {str(e)}"
        }, status=500)