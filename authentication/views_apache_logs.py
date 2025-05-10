import json
import os
from datetime import datetime, timedelta
from django.utils import timezone
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from log_ingestion.models import RawLog, ParsedLog
from threat_detection.models import Threat, BlacklistedIP
from threat_detection.models import Threat, ThreatAnalysis
from django.core.mail import send_mail
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
from alerts.models import NotificationPreference
from .models import ContactMessage, AdminReply, User

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
    
    # Base queryset - filter for Apache logs only - Updated to handle both source types
    logs = ParsedLog.objects.filter(
        Q(raw_log__source__source_type='apache_access') | Q(raw_log__source__source_type='apache'),
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
def apache_logs_api(request):
    """API endpoint for fetching Apache logs data via AJAX"""
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
    
    # Base queryset - filter for Apache logs only - handle both source types
    logs = ParsedLog.objects.filter(
        Q(raw_log__source__source_type='apache_access') | Q(raw_log__source__source_type='apache'),
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
    
    # Pagination
    per_page = 50
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    logs_paginated = logs.order_by('-raw_log__timestamp')[start_idx:end_idx]
    
    # Serialize logs for JSON response
    logs_data = []
    for log in logs_paginated:
        logs_data.append({
            'id': log.id,
            'request_method': log.request_method or 'UNKNOWN',
            'request_path': log.request_path or '/',
            'status_code': log.status_code or 0,
            'source_ip': log.source_ip or '0.0.0.0',
            'response_size': log.response_size,
            'raw_log': {
                'id': log.raw_log.id,
                'timestamp': log.raw_log.timestamp.isoformat()
            }
        })
    
    # Return JSON response
    return JsonResponse({
        'logs': logs_data,
        'stats': {
            'total_logs': total_logs,
            'status_2xx': status_2xx,
            'status_3xx': status_3xx,
            'status_4xx': status_4xx,
            'status_5xx': status_5xx,
            'period_name': period_name
        }
    })