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
    
    # Base queryset - filter for MySQL logs only - Handle both MySQL types
    logs = ParsedLog.objects.filter(
        Q(raw_log__source__source_type='mysql') | Q(raw_log__source__source_type='mysql_error'),
        raw_log__timestamp__gte=start_time
    ).select_related('raw_log')
    
    # Apply query type filter
    if query_type != 'all':
        # Use regex to find query type regardless of leading whitespace/comments
        logs = logs.filter(query__iregex=r'^\s*' + query_type)
    
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
        # Use regex to match query types regardless of whitespace
        count = logs.filter(query__iregex=r'^\s*' + qt).count()
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
def mysql_logs_api(request):
    """API endpoint for fetching MySQL logs data via AJAX"""
    try:
        # Get filter parameters (same as mysql_logs_view)
        time_range = request.GET.get('time_range', '24h')
        query_type = request.GET.get('query_type', 'all')
        execution_time = request.GET.get('execution_time', 'all')
        search_query = request.GET.get('search', '')
        
        try:
            page = int(request.GET.get('page', 1))
        except ValueError:
            page = 1
        
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
        
        # Base queryset - filter for MySQL logs only - Handle both MySQL types
        logs = ParsedLog.objects.filter(
            Q(raw_log__source__source_type='mysql') | Q(raw_log__source__source_type='mysql_error'),
            raw_log__timestamp__gte=start_time
        ).select_related('raw_log')
        
        # Apply query type filter
        if query_type != 'all':
            # Use regex to find query type regardless of leading whitespace/comments
            logs = logs.filter(query__iregex=r'^\s*' + query_type)
        
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
            # Use regex to match query types regardless of whitespace
            count = logs.filter(query__iregex=r'^\s*' + qt).count()
            if count > 0:
                query_types.append({
                    'type': qt,
                    'count': count,
                    'percentage': round(count / total_logs * 100, 1) if total_logs > 0 else 0
                })
        
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
                'user_id': log.user_id or 'system',
                'query': log.query,
                'execution_time': log.execution_time,
                'rows_affected': getattr(log, 'rows_affected', 0),
                'status': log.status,
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
                'slow_queries': slow_queries,
                'normal_queries': total_logs - slow_queries,
                'query_types': query_types,
                'period_name': period_name
            }
        })
    
    except Exception as e:
        # Log the error
        logging.error(f"Error in mysql_logs_api: {str(e)}")
        
        # Return a basic error response
        return JsonResponse({
            'error': 'An error occurred while fetching log data',
            'logs': [],
            'stats': {
                'total_logs': 0,
                'slow_queries': 0,
                'normal_queries': 0,
                'query_types': [],
                'period_name': 'Error'
            }
        }, status=500)

def handle_mysql_logs_error(request, error_message):
    """Helper function to log errors and return a friendly error response"""
    logging.error(f"MySQL logs error: {error_message}")
    
    if 'application/json' in request.headers.get('Accept', ''):
        return JsonResponse({
            'error': 'An error occurred while processing MySQL logs',
            'message': str(error_message),
            'logs': [],
            'stats': {
                'total_logs': 0,
                'slow_queries': 0,
                'normal_queries': 0,
                'query_types': []
            }
        }, status=500)
    else:
        return render(request, 'authentication/mysql_logs.html', {
            'error_message': str(error_message),
            'logs': [],
            'total_logs': 0
        })