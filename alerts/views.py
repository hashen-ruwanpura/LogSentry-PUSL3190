from .models import SMTPConfiguration
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.utils import timezone
from .models import AlertNotification, NotificationPreference, Alert
import json
import logging

logger = logging.getLogger(__name__)

# --- NOTIFICATION VIEWS ---

@login_required
@require_GET
def get_notifications(request):
    """API endpoint to get user's notifications"""
    try:
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
                'threat_id': notification.alert_id,
                'source_ip': notification.source_ip,
                'affected_system': notification.affected_system
            })
        
        return JsonResponse({
            'notifications': notifications_list,
            'unread_count': unread_count
        })
    except Exception as e:
        logger.error(f"Error in get_notifications: {e}", exc_info=True)
        return JsonResponse({'error': str(e)}, status=500)

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
        
        logger.info(f"Notification {notification_id} marked as read by {request.user.username}")
        return JsonResponse({'success': True})
    except AlertNotification.DoesNotExist:
        logger.warning(f"Notification {notification_id} not found for user {request.user.username}")
        return JsonResponse({'success': False, 'error': 'Notification not found'}, status=404)
    except Exception as e:
        logger.error(f"Error marking notification as read: {e}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@require_POST
def mark_all_read(request):
    """Mark all notifications as read"""
    try:
        updated_count = AlertNotification.objects.filter(
            user=request.user,
            is_read=False
        ).update(is_read=True)
        
        logger.info(f"Marked {updated_count} notifications as read for {request.user.username}")
        return JsonResponse({'success': True, 'count': updated_count})
    except Exception as e:
        logger.error(f"Error marking all notifications as read: {e}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@require_GET
def recent_notifications(request):
    """Get only recent unread notifications"""
    try:
        recent_time = timezone.now() - timezone.timedelta(minutes=30)
        notifications = AlertNotification.objects.filter(
            user=request.user,
            is_read=False,
            created_at__gt=recent_time
        ).order_by('-created_at')
        
        notifications_list = []
        for notification in notifications:
            notifications_list.append({
                'id': notification.id,
                'title': notification.title,
                'message': notification.message,
                'severity': notification.severity,
                'is_read': notification.is_read,
                'created_at': notification.created_at.isoformat() if notification.created_at else None,
                'threat_id': notification.alert_id,
                'source_ip': notification.source_ip,
                'affected_system': notification.affected_system
            })
        
        return JsonResponse({
            'notifications': notifications_list
        })
    except Exception as e:
        logger.error(f"Error in recent_notifications: {e}", exc_info=True)
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(lambda u: u.is_superuser)
def smtp_settings_view(request):
    """View for managing SMTP server settings"""
    # Get or create SMTP configuration
    config, created = SMTPConfiguration.objects.get_or_create(
        is_active=True,
        defaults={
            'host': 'smtp.gmail.com',
            'port': 587,
            'username': '',
            'password': '',
            'use_tls': True,
            'use_ssl': False,
            'default_from_email': 'alerts@loganalyzer.com'
        }
    )
    
    if request.method == 'POST':
        try:
            # Update configuration
            config.host = request.POST.get('host')
            config.port = int(request.POST.get('port'))
            config.username = request.POST.get('username')
            
            # Only update password if a new one is provided
            new_password = request.POST.get('password')
            if new_password:
                config.password = new_password
                
            config.use_tls = request.POST.get('use_tls') == 'on'
            config.use_ssl = request.POST.get('use_ssl') == 'on'
            config.default_from_email = request.POST.get('from_email')
            config.save()
            
            return JsonResponse({'success': True, 'message': 'SMTP settings updated successfully'})
        except Exception as e:
            logger.error(f"Error updating SMTP settings: {e}")
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    
    # For GET request, return current settings
    return render(request, 'alerts/smtp_settings.html', {
        'config': config
    })

@login_required
@user_passes_test(lambda u: u.is_superuser)
@csrf_protect
def test_smtp_settings(request):
    """API endpoint to test SMTP settings"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        recipient = data.get('recipient', '')
        
        if not recipient:
            return JsonResponse({'success': False, 'error': 'Recipient email is required'}, status=400)
        
        # Get the SMTP config
        config = SMTPConfiguration.objects.filter(is_active=True).first()
        if not config:
            return JsonResponse({'success': False, 'error': 'No SMTP configuration found'}, status=400)
        
        # Send a test email
        from django.core.mail import send_mail
        
        # Configure email settings
        settings.EMAIL_HOST = config.host
        settings.EMAIL_PORT = config.port
        settings.EMAIL_HOST_USER = config.username
        settings.EMAIL_HOST_PASSWORD = config.password
        settings.EMAIL_USE_TLS = config.use_tls
        settings.EMAIL_USE_SSL = config.use_ssl
        settings.DEFAULT_FROM_EMAIL = config.default_from_email
        
        # Send the test email
        send_mail(
            'Test Email from Log Analyzer',
            'This is a test email to verify your SMTP settings are working correctly.',
            config.default_from_email,
            [recipient],
            fail_silently=False,
            html_message='<h1>Test Email</h1><p>This is a test email to verify your SMTP settings are working correctly.</p>'
        )
        
        return JsonResponse({'success': True, 'message': f'Test email sent to {recipient}'})
    except Exception as e:
        logger.error(f"Error sending test email: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

def events_view(request):
    """View for events page"""
    return render(request, 'authentication/events.html')

@login_required
def alerts_list(request):
    """View to display list of alerts"""
    # Get all alerts, sorted by most recent first
    alerts = Alert.objects.all().order_by('-created_at')
    
    # Count alerts by severity
    severity_counts = {
        'critical': Alert.objects.filter(severity='critical').count(),
        'high': Alert.objects.filter(severity='high').count(),
        'medium': Alert.objects.filter(severity='medium').count(),
        'low': Alert.objects.filter(severity='low').count()
    }
    
    context = {
        'alerts': alerts,
        'severity_counts': severity_counts,
        'total_alerts': alerts.count()
    }
    
    return render(request, 'alerts/alerts_list.html', context)
