from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q
from django.utils import timezone
from log_ingestion.models import LogSource, RawLog, ParsedLog
import json
import csv
from datetime import datetime, timedelta
from django.template.exceptions import TemplateDoesNotExist

def is_superuser(user):
    """Helper function to check if a user is a superuser"""
    return user.is_authenticated and user.is_superuser

@login_required
@user_passes_test(is_superuser, login_url='/')
def logs_view(request):
    """Admin log analysis page"""
    template_paths = [
        'frontend/admin/loganalysis.html',
        'admin/loganalysis.html',
        'loganalysis.html'
    ]
    
    for template_path in template_paths:
        try:
            return render(request, template_path)
        except TemplateDoesNotExist:
            continue
    
    # If no template is found, return an error
    return HttpResponse("Log analysis template not found. Please make sure the template file exists.", status=500)

@login_required
@user_passes_test(is_superuser)
def api_logs_list(request):
    """API endpoint to get paginated list of logs"""
    # Get query parameters for filtering and pagination
    source = request.GET.get('source', '')
    severity = request.GET.get('severity', '')
    search = request.GET.get('search', '')
    start_date = request.GET.get('start_date', '')
    end_date = request.GET.get('end_date', '')
    page = request.GET.get('page', 1)
    
    # Start with all logs, ordered by timestamp descending
    logs = ParsedLog.objects.all().order_by('-timestamp')
    
    # Apply source filter
    if source:
        logs = logs.filter(source__name__iexact=source)
    
    # Apply severity filter
    if severity:
        logs = logs.filter(severity__iexact=severity)
    
    # Apply search filter (search in message field)
    if search:
        logs = logs.filter(message__icontains=search)
    
    # Apply date range filter
    if start_date:
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            logs = logs.filter(timestamp__gte=start_date)
        except ValueError:
            pass
    
    if end_date:
        try:
            # Add one day to end_date to include logs from that day
            end_date = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            logs = logs.filter(timestamp__lt=end_date)
        except ValueError:
            pass
    
    # Paginate results
    paginator = Paginator(logs, 20)  # Show 20 logs per page
    
    try:
        logs_page = paginator.page(page)
    except PageNotAnInteger:
        logs_page = paginator.page(1)
    except EmptyPage:
        logs_page = paginator.page(paginator.num_pages)
    
    # Format log data for response
    logs_data = []
    for log in logs_page:
        logs_data.append({
            'id': log.id,
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'source': log.source.name if log.source else 'unknown',
            'event_type': log.event_type if hasattr(log, 'event_type') else 'log',
            'severity': log.severity if hasattr(log, 'severity') else 'low',
            'message': log.message,
            'ip_address': log.ip_address if hasattr(log, 'ip_address') else '-',
            'user': log.user if hasattr(log, 'user') else '-'
        })
    
    # Return JSON response
    return JsonResponse({
        'logs': logs_data,
        'total_pages': paginator.num_pages,
        'current_page': logs_page.number
    })

@login_required
@user_passes_test(is_superuser)
def api_log_detail(request, log_id):
    """API endpoint to get details of a specific log"""
    log = get_object_or_404(ParsedLog, id=log_id)
    raw_log = log.raw_log.content if log.raw_log else "Raw log not available"
    
    # Format log data for response
    log_data = {
        'id': log.id,
        'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'source': log.source.name if log.source else 'unknown',
        'event_type': log.event_type if hasattr(log, 'event_type') else 'log',
        'severity': log.severity if hasattr(log, 'severity') else 'low',
        'message': log.message,
        'ip_address': log.ip_address if hasattr(log, 'ip_address') else '-',
        'user': log.user if hasattr(log, 'user') else '-',
        'raw_log': raw_log
    }
    
    return JsonResponse(log_data)

@login_required
@user_passes_test(is_superuser)
def api_log_export(request, log_id):
    """API endpoint to export a specific log"""
    log = get_object_or_404(ParsedLog, id=log_id)
    raw_log = log.raw_log.content if log.raw_log else "Raw log not available"
    
    # Create response with CSV file
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="log_{log_id}.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Field', 'Value'])
    writer.writerow(['ID', log.id])
    writer.writerow(['Timestamp', log.timestamp.strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow(['Source', log.source.name if log.source else 'unknown'])
    writer.writerow(['Event Type', log.event_type if hasattr(log, 'event_type') else 'log'])
    writer.writerow(['Severity', log.severity if hasattr(log, 'severity') else 'low'])
    writer.writerow(['Message', log.message])
    writer.writerow(['IP Address', log.ip_address if hasattr(log, 'ip_address') else '-'])
    writer.writerow(['User', log.user if hasattr(log, 'user') else '-'])
    writer.writerow(['Raw Log', raw_log])
    
    return response