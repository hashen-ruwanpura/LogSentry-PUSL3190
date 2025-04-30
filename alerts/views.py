from .models import SMTPConfiguration
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.utils import timezone
from .models import AlertNotification, NotificationPreference
import json
import logging

logger = logging.getLogger(__name__)

# --- NOTIFICATION VIEWS ---

# Frontend: templates/alerts/notifications.html
# Purpose: Displays all notifications for the current user
# Features: Lists recent alerts with unread count
@login_required
def notifications_view(request):
    """View all notifications for the current user"""
    # Get user's notifications
    notifications = AlertNotification.objects.filter(user=request.user).order_by('-created_at')[:50]
    
    return render(request, 'alerts/notifications.html', {
        'notifications': notifications,
        'unread_count': notifications.filter(is_read=False).count()
    })

# Frontend: No direct template (API endpoint for notifications bell in header)
# Purpose: JSON API for retrieving notifications via AJAX/Fetch
# Usage: Called by JavaScript in base.html to update notification bell
@login_required
def api_notifications(request):
    """API endpoint to get notifications for the current user"""
    # Get last 20 notifications
    notifications = AlertNotification.objects.filter(user=request.user).order_by('-created_at')[:20]
    unread_count = notifications.filter(is_read=False).count()
    
    # Convert to dict for JSON serialization
    notification_data = []
    for notif in notifications:
        notification_data.append({
            'id': notif.id,
            'title': notif.title,
            'message': notif.message,
            'severity': notif.severity,
            'alert_id': notif.alert_id,
            'source_ip': notif.source_ip,
            'affected_system': notif.affected_system,
            'is_read': notif.is_read,
            'timestamp': notif.created_at.isoformat()
        })
    
    return JsonResponse({
        'notifications': notification_data,
        'unread_count': unread_count
    })

# Frontend: No direct template (API endpoint for notifications.html)
# Purpose: Mark individual notification as read via AJAX
# Usage: Called by JavaScript when user clicks on notification
@login_required
@require_POST
def api_mark_notification_read(request, notification_id):
    """API endpoint to mark a notification as read"""
    try:
        notification = AlertNotification.objects.get(id=notification_id, user=request.user)
        notification.is_read = True
        notification.save()
        return JsonResponse({'success': True})
    except Exception as e:
        logger.error(f"Error marking notification as read: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=400)

# Frontend: No direct template (API endpoint for notifications.html)
# Purpose: Mark all notifications as read via AJAX
# Usage: Called by JavaScript when user clicks "Mark All Read" button
@login_required
@require_POST
def api_mark_all_read(request):
    """API endpoint to mark all notifications as read"""
    try:
        AlertNotification.objects.filter(user=request.user, is_read=False).update(
            is_read=True
        )
        return JsonResponse({'success': True})
    except Exception as e:
        logger.error(f"Error marking all notifications as read: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=400)

# Frontend: templates/alerts/preferences.html
# Purpose: User interface for notification preferences
# Features: Configure email, in-app, and push notification settings
@login_required
def notification_preferences(request):
    """View and update notification preferences"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            preferences = NotificationPreference.objects.get(user=request.user)
            
            # Update email preferences
            if 'email_alerts' in data:
                preferences.email_alerts = data['email_alerts']
            if 'email_threshold' in data:
                preferences.email_threshold = data['email_threshold']
            
            # Update in-app preferences
            if 'in_app_alerts' in data:
                preferences.in_app_alerts = data['in_app_alerts'] 
            if 'in_app_threshold' in data:
                preferences.in_app_threshold = data['in_app_threshold']
            
            preferences.save()
            return JsonResponse({'success': True})
        except Exception as e:
            logger.error(f"Error updating notification preferences: {e}")
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    else:
        preferences = NotificationPreference.objects.get(user=request.user)
        return render(request, 'alerts/preferences.html', {
            'preferences': preferences
        })

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
