from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from .models import AlertNotification, Alert

@login_required
def get_notifications(request):
    """API endpoint to get user's notifications"""
    notifications = AlertNotification.objects.filter(
        user=request.user
    ).order_by('-created_at')[:50]
    
    unread_count = AlertNotification.objects.filter(
        user=request.user, 
        is_read=False
    ).count()
    
    notifications_list = []
    for notification in notifications:
        notifications_list.append({
            'id': notification.id,
            'title': notification.title,
            'message': notification.message,
            'severity': notification.severity,
            'is_read': notification.is_read,
            'created_at': notification.created_at.isoformat() if notification.created_at else None,
            'threat_id': notification.alert_id
        })
    
    return JsonResponse({
        'notifications': notifications_list,
        'unread_count': unread_count
    })

@login_required
@require_POST
def mark_notification_read(request, notification_id):
    """Mark notification as read"""
    try:
        notification = AlertNotification.objects.get(
            id=notification_id,
            user=request.user
        )
        notification.is_read = True
        notification.save()
        return JsonResponse({'success': True})
    except AlertNotification.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Notification not found'}, status=404)

@login_required
@require_POST
def mark_all_read(request):
    """Mark all notifications as read"""
    AlertNotification.objects.filter(
        user=request.user,
        is_read=False
    ).update(is_read=True)
    return JsonResponse({'success': True})

@login_required
def recent_notifications(request):
    """Get recent notifications for the current user"""
    # Get unread notifications from last 24 hours 
    recent_time = timezone.now() - timezone.timedelta(hours=24)
    debug = request.GET.get('debug', 'true') == 'true'  # Default to debug mode
    
    # Always include source_ip and affected_system in response
    if debug:
        # In debug mode, get both read and unread notifications
        notifications = AlertNotification.objects.filter(
            user=request.user,
            created_at__gte=recent_time
        ).order_by('-created_at')[:20]
    else:
        # Normal mode - just get unread recent notifications
        notifications = AlertNotification.objects.filter(
            user=request.user,
            is_read=False,
            created_at__gte=recent_time
        ).order_by('-created_at')[:10]
    
    # Debug info
    print(f"Found {notifications.count()} notifications for user {request.user.username}")
    
    # Convert to JSON-friendly format - include ALL fields
    notification_data = [{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'severity': n.severity,
        'is_read': n.is_read,
        'created_at': n.created_at.isoformat(),
        'threat_id': n.threat_id,
        'source_ip': n.source_ip,
        'affected_system': n.affected_system
    } for n in notifications]
    
    return JsonResponse({
        'notifications': notification_data,
        'debug_info': {
            'query_time': timezone.now().isoformat(),
            'user': request.user.username,
            'debug_mode': debug,
            'query_params': dict(request.GET)
        } if debug else {}
    })

@login_required
@require_POST
def register_device(request):
    """Register a device token for notifications"""
    return JsonResponse({'success': True})