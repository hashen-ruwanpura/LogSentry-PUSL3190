from datetime import datetime, timedelta
from django.utils import timezone
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.models import User
from django.core.paginator import Paginator, EmptyPage
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_POST
from django.db.models import Q
import csv
import logging

from authentication.models import ConfigAuditLog
from log_ingestion.models import LogSource

logger = logging.getLogger(__name__)

# Helper function to check if a user is a superuser
def is_superuser(user):
    return user.is_authenticated and user.is_superuser

@login_required
@user_passes_test(is_superuser, login_url='/')
def audit_logs_view(request):
    """
    View for displaying configuration audit logs
    Shows a timeline of log path changes with user details
    """
    # Get filter parameters
    time_range = request.GET.get('time_range', '30d')
    change_type = request.GET.get('change_type', 'all')
    user_filter = request.GET.get('user', 'all')
    status_filter = request.GET.get('status', 'all')
    search_query = request.GET.get('search', '')
    page = int(request.GET.get('page', 1))
    
    # Determine time period based on range parameter
    now = timezone.now()
    if time_range == '24h':
        start_time = now - timedelta(hours=24)
        period_name = 'Last 24 Hours'
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
        period_name = 'Last 7 Days'
    elif time_range == '30d':
        start_time = now - timedelta(days=30)
        period_name = 'Last 30 Days'
    elif time_range == 'all':
        start_time = now - timedelta(days=365*5)  # 5 years back should cover all
        period_name = 'All Time'
    else:
        start_time = now - timedelta(days=30)  # Default to 30 days
        period_name = 'Last 30 Days'
    
    # Get base queryset
    try:
        logs = ConfigAuditLog.objects.filter(timestamp__gte=start_time)
        
        # Apply filters
        if change_type != 'all':
            logs = logs.filter(change_type=change_type)
        
        if user_filter != 'all':
            logs = logs.filter(user__username=user_filter)
            
        if status_filter != 'all':
            logs = logs.filter(status=status_filter)
        
        if search_query:
            logs = logs.filter(
                Q(previous_value__icontains=search_query) | 
                Q(new_value__icontains=search_query) |
                Q(description__icontains=search_query)
            )
        
        # Count pending changes (active changes that could be reverted)
        pending_count = logs.filter(status='active').count()
        
        # Get all unique users for the filter dropdown
        all_users = User.objects.filter(
            id__in=logs.values_list('user', flat=True).distinct()
        ).values_list('username', flat=True)
        
        # Pagination
        per_page = 25
        paginator = Paginator(logs, per_page)
        
        try:
            logs_page = paginator.page(page)
        except EmptyPage:
            logs_page = paginator.page(paginator.num_pages)
            page = paginator.num_pages
    except Exception as e:
        logger.error(f"Error retrieving audit logs: {str(e)}", exc_info=True)
        logs_page = []
        all_users = []
        pending_count = 0
        paginator = None
    
    # Build context for template
    context = {
        'logs': logs_page,
        'time_range': time_range,
        'period_name': period_name,
        'change_type': change_type,
        'user_filter': user_filter,
        'status_filter': status_filter,
        'search_query': search_query,
        'page': page,
        'num_pages': paginator.num_pages if paginator else 1,
        'users': all_users,
        'pending_count': pending_count,
    }
    
    return render(request, 'admin/auditlogs.html', context)

@login_required
@user_passes_test(is_superuser, login_url='/')
@require_POST
def revert_config_change(request, log_id):
    """API endpoint to revert a configuration change"""
    try:
        # Get the audit log entry
        log = ConfigAuditLog.objects.get(id=log_id, status='active')
        
        # Handle different change types
        if log.change_type == 'apache_path':
            # Revert Apache log path
            apache_source = LogSource.objects.get(name='Apache Web Server')
            apache_source.file_path = log.previous_value
            apache_source.save()
            
        elif log.change_type == 'mysql_path':
            # Revert MySQL log path
            mysql_source = LogSource.objects.get(name='MySQL Database Server')
            mysql_source.file_path = log.previous_value
            mysql_source.save()
            
        # Mark the log as reverted
        log.status = 'reverted'
        log.reverted_by = request.user
        log.reverted_at = timezone.now()
        log.save()
        
        # Create a new audit log entry for the revert action
        ConfigAuditLog.objects.create(
            user=request.user,
            change_type=log.change_type,
            previous_value=log.new_value,
            new_value=log.previous_value,
            description=f"Reverted change: {log.description}",
            source_ip=request.META.get('REMOTE_ADDR')
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Configuration change has been reverted successfully'
        })
        
    except ConfigAuditLog.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Audit log entry not found or already reverted'
        }, status=404)
        
    except Exception as e:
        logger.error(f"Error reverting config change: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@user_passes_test(is_superuser, login_url='/')
def export_audit_logs(request):
    """Export audit logs to CSV"""
    # Get filter parameters
    time_range = request.GET.get('time_range', '30d')
    change_type = request.GET.get('change_type', 'all')
    user_filter = request.GET.get('user', 'all')
    status_filter = request.GET.get('status', 'all')
    search_query = request.GET.get('search', '')
    
    # Determine time period
    now = timezone.now()
    if time_range == '24h':
        start_time = now - timedelta(hours=24)
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
    elif time_range == 'all':
        start_time = now - timedelta(days=365*5)
    else:  # Default to 30d
        start_time = now - timedelta(days=30)
    
    # Get logs with filters
    logs = ConfigAuditLog.objects.filter(timestamp__gte=start_time)
    
    if change_type != 'all':
        logs = logs.filter(change_type=change_type)
    
    if user_filter != 'all':
        logs = logs.filter(user__username=user_filter)
        
    if status_filter != 'all':
        logs = logs.filter(status=status_filter)
    
    if search_query:
        logs = logs.filter(
            Q(previous_value__icontains=search_query) | 
            Q(new_value__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    # Create HTTP response with CSV
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="audit_logs_{now.strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'User', 'Change Type', 'Description', 'Previous Value', 'New Value', 'Status'])
    
    for log in logs:
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.user.username if log.user else 'Unknown',
            log.get_change_type_display() if hasattr(log, 'get_change_type_display') else log.change_type,
            log.description,
            log.previous_value,
            log.new_value,
            log.get_status_display() if hasattr(log, 'get_status_display') else log.status
        ])
    
    return response