from django.db import models
from django.conf import settings
import requests
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# --- WEB PUSH NOTIFICATION MODELS & SERVICES ---

# Purpose: Store Firebase Cloud Messaging configuration
# Usage: Used by PushNotifier to send browser/mobile notifications
# Admin UI: Configured via Django admin interface
class FCMConfiguration(models.Model):
    """Model to store Firebase Cloud Messaging configuration"""
    api_key = models.CharField(max_length=255)
    project_id = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"FCM Config: {self.project_id}"
    
    @classmethod
    def get_active_config(cls):
        """Get the active FCM configuration"""
        try:
            return cls.objects.filter(is_active=True).first()
        except Exception as e:
            logger.error(f"Error retrieving FCM config: {e}")
            return None

# Purpose: Store user device tokens for push notifications
# Usage: Registered by JavaScript in frontend when user enables notifications
# Related Frontend: JavaScript in notification-service.js registers devices
class UserDevice(models.Model):
    """Model to store user device tokens for push notifications"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    device_token = models.CharField(max_length=255)
    device_type = models.CharField(max_length=20)  # web, android, ios
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('user', 'device_token')
        
    def __str__(self):
        return f"Device: {self.user.username} ({self.device_type})"

# Purpose: Track push notifications sent to users
# Usage: Historical record of sent push notifications
# Admin UI: Viewable in Django admin for debugging
class PushNotification(models.Model):
    """Model to track push notifications sent"""
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    title = models.CharField(max_length=255)
    body = models.TextField()
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    device = models.ForeignKey(UserDevice, on_delete=models.SET_NULL, null=True, blank=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    related_threat_id = models.IntegerField(null=True, blank=True)
    status = models.CharField(max_length=20, default='pending')  # pending, sent, failed
    error_message = models.TextField(blank=True, null=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Push: {self.title} ({self.status})"

# Purpose: Service to send browser push notifications
# Usage: Called by AlertService to send push notifications
# Related Frontend: Notifications appear in user's browser/mobile even when app is closed
class PushNotifier:
    """Service class for sending web push notifications via FCM"""
    
    @staticmethod
    def send_to_user(user, title, body, data=None, severity='medium', threat_id=None):
        """Send push notification to all devices of a user"""
        devices = UserDevice.objects.filter(user=user, is_active=True)
        if not devices:
            logger.info(f"No active devices found for user {user.username}")
            return False
            
        success = False
        for device in devices:
            if PushNotifier.send_to_device(device, title, body, data, severity, threat_id):
                success = True
                
        return success
    
    @staticmethod
    def send_to_device(device, title, body, data=None, severity='medium', threat_id=None):
        """Send push notification to a specific device"""
        config = FCMConfiguration.get_active_config()
        if not config:
            logger.error("No active FCM configuration found")
            return False
            
        # Create notification record
        notification = PushNotification(
            title=title,
            body=body,
            user=device.user,
            device=device,
            severity=severity,
            related_threat_id=threat_id
        )
        notification.save()
        
        # Prepare FCM message
        fcm_data = data or {}
        fcm_data.update({
            'threat_id': threat_id,
            'severity': severity,
            'time': datetime.now().isoformat()
        })
        
        message = {
            'to': device.device_token,
            'notification': {
                'title': title,
                'body': body,
                'icon': '/static/images/alert_icon.png',
                'click_action': f'/alert/{threat_id}/' if threat_id else '/events/'
            },
            'data': fcm_data
        }
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'key={config.api_key}'
        }
        
        try:
            response = requests.post(
                'https://fcm.googleapis.com/fcm/send',
                headers=headers,
                data=json.dumps(message)
            )
            
            response_data = response.json()
            
            if response.status_code == 200 and response_data.get('success', 0) == 1:
                notification.status = 'sent'
                notification.sent_at = datetime.now()
                notification.save()
                logger.info(f"Push notification sent successfully to device {device.id}")
                return True
            else:
                error = response_data.get('results', [{}])[0].get('error', 'Unknown error')
                notification.status = 'failed'
                notification.error_message = error
                notification.save()
                logger.error(f"Push notification failed: {error}")
                
                # If the token is invalid, mark the device as inactive
                if error == 'InvalidRegistration' or error == 'NotRegistered':
                    device.is_active = False
                    device.save()
                    
                return False
                
        except Exception as e:
            notification.status = 'failed'
            notification.error_message = str(e)
            notification.save()
            logger.error(f"Error sending push notification: {e}")
            return False