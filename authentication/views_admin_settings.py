from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.template.exceptions import TemplateDoesNotExist
from django.core.mail import send_mail
from django.conf import settings as django_settings
from django.utils import timezone
from .models import SystemSettings
import json
import logging
import os
import subprocess

logger = logging.getLogger(__name__)

def is_superuser(user):
    """Helper function to check if a user is a superuser"""
    return user.is_authenticated and user.is_superuser

@login_required
@user_passes_test(is_superuser, login_url='/')
@ensure_csrf_cookie
def settings_view(request):
    """Admin settings page view"""
    template_paths = [
        'frontend/admin/adminsettings.html',
        'admin/adminsettings.html',
        'adminsettings.html'
    ]
    
    for template_path in template_paths:
        try:
            return render(request, template_path)
        except TemplateDoesNotExist:
            continue
    
    return render(request, 'error.html', {'message': 'Settings template not found'})

@login_required
@user_passes_test(is_superuser)
def api_settings_get(request):
    """API endpoint to get all settings"""
    try:
        # Get all settings from database
        settings_data = SystemSettings.get_all_settings()
        
        # If settings don't exist yet, return default settings
        if not settings_data:
            settings_data = get_default_settings()
        
        return JsonResponse({
            'settings': settings_data,
            'last_updated': SystemSettings.get_last_updated() or 'Never'
        })
    except Exception as e:
        logger.error(f"Error retrieving settings: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def api_settings_save(request):
    """API endpoint to save settings"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        section = data.get('section', '')
        settings_data = data.get('data', {})
        
        if not section or not settings_data:
            return JsonResponse({'error': 'Invalid request data'}, status=400)
            
        # Save settings to database
        SystemSettings.save_settings(section, settings_data, request.user)
        
        # Get updated timestamp
        last_updated = SystemSettings.get_last_updated()
        
        # Log the settings change
        logger.info(f"Settings updated - section: {section} by user: {request.user.username}")
        
        return JsonResponse({
            'success': True,
            'message': f'{section.capitalize()} settings saved successfully',
            'last_updated': last_updated
        })
    except Exception as e:
        logger.error(f"Error saving settings: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def api_settings_reset(request):
    """API endpoint to reset settings to defaults"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        section = data.get('section', '')
        
        if not section:
            return JsonResponse({'error': 'Invalid request data'}, status=400)
            
        # Reset settings to defaults
        SystemSettings.reset_settings(section)
        
        # Log the reset
        logger.info(f"Settings reset to defaults - section: {section} by user: {request.user.username}")
        
        return JsonResponse({
            'success': True,
            'message': f'{section.capitalize()} settings reset to defaults'
        })
    except Exception as e:
        logger.error(f"Error resetting settings: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def api_test_email(request):
    """API endpoint to send a test email"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        recipient = data.get('recipient', '')
        
        if not recipient:
            return JsonResponse({'error': 'Recipient email required'}, status=400)
        
        # Get email settings from database or use defaults
        email_settings = SystemSettings.get_section('notification')
        sender_email = email_settings.get('senderEmail', django_settings.DEFAULT_FROM_EMAIL)
        
        # Send test email
        send_mail(
            subject='Test Email from ThreatGuard',
            message='This is a test email from your ThreatGuard system. If you received this email, your email settings are configured correctly.',
            from_email=sender_email,
            recipient_list=[recipient],
            fail_silently=False,
        )
        
        # Log the test email
        logger.info(f"Test email sent to: {recipient} by user: {request.user.username}")
        
        return JsonResponse({
            'success': True,
            'message': f'Test email sent to {recipient}'
        })
    except Exception as e:
        logger.error(f"Error sending test email: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def api_manual_backup(request):
    """API endpoint to start a manual backup"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        # Get backup directory from settings
        backup_settings = SystemSettings.get_section('backup')
        backup_dir = backup_settings.get('backupDirectory', '/var/backups/threatguard/')
        
        # Ensure backup directory exists
        os.makedirs(backup_dir, exist_ok=True)
        
        # Generate timestamp for backup filename
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(backup_dir, f'manual_backup_{timestamp}.db')
        
        # In a real implementation, you would call Django's dumpdata or a custom backup script
        # For this example, we'll just simulate it
        # Example: subprocess.run(['python', 'manage.py', 'dumpdata', '--indent', '2', f'--output={backup_file}'])
        
        # Log the backup initiation
        logger.info(f"Manual backup initiated by user: {request.user.username}")
        
        return JsonResponse({
            'success': True,
            'message': 'Manual backup started successfully',
            'backup_file': backup_file
        })
    except Exception as e:
        logger.error(f"Error starting backup: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

def get_default_settings():
    """Return default settings for all sections"""
    return {
        'general': {
            'systemName': 'ThreatGuard Detection System',
            'organization': 'Example Inc.',
            'adminContact': 'admin@example.com',
            'defaultTheme': 'light',
            'sessionTimeout': 30,
            'itemsPerPage': 25,
        },
        'security': {
            'minPasswordLength': 8,
            'requireUppercase': True,
            'requireNumbers': True,
            'requireSpecial': False,
            'passwordExpiry': 90,
            'accountLockout': 5,
            'lockoutDuration': 30,
        },
        'notification': {
            'enableEmailNotifications': True,
            'smtpServer': 'smtp.example.com',
            'smtpPort': 587,
            'smtpUsername': 'notifications@example.com',
            'smtpPassword': '',
            'useSmtpTLS': True,
            'senderEmail': 'alerts@threatguard.example.com',
            'alertRecipients': 'admin@example.com, security@example.com',
            'notifyCritical': True,
            'notifyHigh': True,
            'notifyMedium': False,
            'notifyLow': False,
        },
        'backup': {
            'enableAutoBackup': True,
            'backupFrequency': 'daily',
            'backupRetention': 30,
            'backupDirectory': '/var/backups/threatguard/',
            'apacheLogRetention': 90,
            'mysqlLogRetention': 90,
            'alertRetention': 180,
        }
    }