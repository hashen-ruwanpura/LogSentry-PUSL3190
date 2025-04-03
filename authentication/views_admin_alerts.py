from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q, Count
from django.utils import timezone
from alerts.models import Alert, AlertNote
import json
import csv
from datetime import datetime, timedelta
from django.template.exceptions import TemplateDoesNotExist

def is_superuser(user):
    """Helper function to check if a user is a superuser"""
    return user.is_authenticated and user.is_superuser

@login_required
@user_passes_test(is_superuser, login_url='/')
def alerts_view(request):
    """Admin alerts management page"""
    template_paths = [
        'frontend/admin/alerts.html',
        'admin/alerts.html',
        'alerts.html'
    ]
    
    for template_path in template_paths:
        try:
            return render(request, template_path)
        except TemplateDoesNotExist:
            continue
    
    # If no template is found, return an error
    return HttpResponse("Alerts template not found. Please make sure the template file exists.", status=500)

@login_required
@user_passes_test(is_superuser)
def api_alerts_list(request):
    """API endpoint to get paginated list of alerts"""
    # Get query parameters for filtering and pagination
    severity = request.GET.get('severity', '')
    status = request.GET.get('status', '')
    alert_type = request.GET.get('type', '')
    start_date = request.GET.get('start_date', '')
    end_date = request.GET.get('end_date', '')
    page = request.GET.get('page', 1)
    
    # Start with all alerts, ordered by timestamp descending
    alerts = Alert.objects.all().order_by('-timestamp')
    
    # Apply severity filter
    if severity:
        alerts = alerts.filter(severity=severity)
    
    # Apply status filter
    if status:
        alerts = alerts.filter(status=status)
    
    # Apply type filter
    if alert_type:
        alerts = alerts.filter(type=alert_type)
    
    # Apply date range filter
    if start_date:
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            alerts = alerts.filter(timestamp__gte=start_date)
        except ValueError:
            pass
    
    if end_date:
        try:
            # Add one day to end_date to include alerts from that day
            end_date = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            alerts = alerts.filter(timestamp__lt=end_date)
        except ValueError:
            pass
    
    # Paginate results
    paginator = Paginator(alerts, 15)  # Show 15 alerts per page
    
    try:
        alerts_page = paginator.page(page)
    except PageNotAnInteger:
        alerts_page = paginator.page(1)
    except EmptyPage:
        alerts_page = paginator.page(paginator.num_pages)
    
    # Format alert data for response
    alerts_data = []
    for alert in alerts_page:
        alerts_data.append({
            'id': alert.id,
            'timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'type': alert.type,
            'source': alert.source,
            'severity': alert.severity,
            'status': alert.status,
            'description': alert.description
        })
    
    # Return JSON response
    return JsonResponse({
        'alerts': alerts_data,
        'total_pages': paginator.num_pages,
        'current_page': alerts_page.number
    })

@login_required
@user_passes_test(is_superuser)
def api_alert_detail(request, alert_id):
    """API endpoint to get details of a specific alert"""
    alert = get_object_or_404(Alert, id=alert_id)
    notes = AlertNote.objects.filter(alert=alert).order_by('-timestamp').first()
    
    # Format alert data for response
    alert_data = {
        'id': alert.id,
        'timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'type': alert.type,
        'source': alert.source,
        'severity': alert.severity,
        'status': alert.status,
        'description': alert.description,
        'ip_address': alert.ip_address,
        'user': alert.user,
        'affected_systems': alert.affected_systems,
        'mitre_tactics': alert.mitre_tactics.split(',') if alert.mitre_tactics else [],
        'recommendation': alert.recommendation,
        'notes': notes.content if notes else ''
    }
    
    return JsonResponse(alert_data)

@login_required
@user_passes_test(is_superuser)
def api_alert_notes(request, alert_id):
    """API endpoint to update notes for a specific alert"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    alert = get_object_or_404(Alert, id=alert_id)
    
    try:
        data = json.loads(request.body)
        notes = data.get('notes', '')
        
        # Create new note
        AlertNote.objects.create(
            alert=alert,
            content=notes,
            created_by=request.user
        )
        
        return JsonResponse({'success': True, 'message': 'Notes saved successfully'})
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def api_alert_status(request, alert_id):
    """API endpoint to update the status of a specific alert"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    alert = get_object_or_404(Alert, id=alert_id)
    
    try:
        data = json.loads(request.body)
        status = data.get('status', '')
        
        if status not in ['new', 'investigating', 'resolved', 'ignored']:
            return JsonResponse({'error': 'Invalid status'}, status=400)
        
        alert.status = status
        alert.save()
        
        # Log status change
        AlertNote.objects.create(
            alert=alert,
            content=f"Status changed to '{status}' by {request.user}",
            created_by=request.user
        )
        
        return JsonResponse({'success': True, 'message': 'Status updated successfully'})
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def api_alert_escalate(request, alert_id):
    """API endpoint to escalate an alert"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    alert = get_object_or_404(Alert, id=alert_id)
    
    try:
        # In a real application, this would trigger notifications to the security team
        # For this example, we'll just log the escalation
        AlertNote.objects.create(
            alert=alert,
            content=f"Alert escalated by {request.user}. Security team notified.",
            created_by=request.user
        )
        
        return JsonResponse({'success': True, 'message': 'Alert escalated successfully'})
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def api_alert_export(request, alert_id):
    """API endpoint to export a specific alert"""
    alert = get_object_or_404(Alert, id=alert_id)
    notes = AlertNote.objects.filter(alert=alert).order_by('-timestamp')
    
    # Create response with CSV file
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="alert_{alert_id}.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Field', 'Value'])
    writer.writerow(['Alert ID', alert.id])
    writer.writerow(['Timestamp', alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow(['Type', alert.type])
    writer.writerow(['Source', alert.source])
    writer.writerow(['Severity', alert.severity])
    writer.writerow(['Status', alert.status])
    writer.writerow(['Description', alert.description])
    writer.writerow(['IP Address', alert.ip_address or 'N/A'])
    writer.writerow(['User', alert.user or 'N/A'])
    writer.writerow(['Affected Systems', alert.affected_systems or 'N/A'])
    writer.writerow(['MITRE ATT&CK Tactics', alert.mitre_tactics or 'N/A'])
    writer.writerow(['Recommendation', alert.recommendation or 'N/A'])
    writer.writerow([])
    writer.writerow(['Notes History'])
    writer.writerow(['Timestamp', 'User', 'Note'])
    
    for note in notes:
        writer.writerow([
            note.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            note.created_by.username if note.created_by else 'Unknown',
            note.content
        ])
    
    return response

@login_required
@user_passes_test(is_superuser)
def api_alert_counts(request):
    """API endpoint to get alert counts by severity"""
    # Get counts of alerts by severity where status is not resolved or ignored
    counts = Alert.objects.exclude(status__in=['resolved', 'ignored']) \
        .values('severity') \
        .annotate(count=Count('id'))
    
    # Convert to dictionary format
    result = {item['severity']: item['count'] for item in counts}
    
    # Ensure all severities are represented
    for severity in ['critical', 'high', 'medium', 'low']:
        if severity not in result:
            result[severity] = 0
    
    return JsonResponse(result)