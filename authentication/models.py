from django.db import models
from django.contrib.auth.models import User
import json
from django.utils import timezone
from django.core.serializers.json import DjangoJSONEncoder
from django.conf import settings

class SystemSettings(models.Model):
    """Model for storing system settings"""
    section = models.CharField(max_length=50)
    settings_key = models.CharField(max_length=100)
    settings_value = models.TextField()
    last_updated = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    class Meta:
        unique_together = ['section', 'settings_key']
        
    @classmethod
    def get_setting(cls, section, key, default=None):
        """Get a single setting value"""
        try:
            setting = cls.objects.get(section=section, settings_key=key)
            return json.loads(setting.settings_value)
        except cls.DoesNotExist:
            return default
        except json.JSONDecodeError:
            return default
    
    @classmethod
    def set_setting(cls, section, key, value, user=None):
        """Set a single setting value"""
        setting, created = cls.objects.update_or_create(
            section=section,
            settings_key=key,
            defaults={
                'settings_value': json.dumps(value),
                'updated_by': user
            }
        )
        return setting
    
    @classmethod
    def get_section(cls, section):
        """Get all settings for a section"""
        settings_dict = {}
        settings = cls.objects.filter(section=section)
        
        for setting in settings:
            try:
                settings_dict[setting.settings_key] = json.loads(setting.settings_value)
            except json.JSONDecodeError:
                settings_dict[setting.settings_key] = setting.settings_value
                
        return settings_dict
    
    @classmethod
    def save_settings(cls, section, data, user=None):
        """Save all settings for a section"""
        for key, value in data.items():
            cls.set_setting(section, key, value, user)
    
    @classmethod
    def get_all_settings(cls):
        """Get all settings organized by section"""
        all_settings = {}
        sections = cls.objects.values_list('section', flat=True).distinct()
        
        for section in sections:
            all_settings[section] = cls.get_section(section)
            
        return all_settings
    
    @classmethod
    def get_last_updated(cls):
        """Get the last updated timestamp"""
        try:
            latest = cls.objects.latest('last_updated')
            return latest.last_updated.strftime('%Y-%m-%d %H:%M:%S')
        except cls.DoesNotExist:
            return None
    
    @classmethod
    def reset_settings(cls, section):
        """Reset settings for a section to defaults"""
        cls.objects.filter(section=section).delete()
    
    def __str__(self):
        return f"{self.section}.{self.settings_key}"

class UserPreference(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='preferences')
    settings = models.JSONField(default=dict, encoder=DjangoJSONEncoder)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.username}'s preferences"

class ContactMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    is_replied = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.name}: {self.subject}"
    
    class Meta:
        ordering = ['-created_at']

class AdminReply(models.Model):
    contact_message = models.ForeignKey(ContactMessage, on_delete=models.CASCADE, related_name='replies')
    admin_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    reply_text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Reply to {self.contact_message.name}"
    
    class Meta:
        ordering = ['created_at']

class UserDeviceToken(models.Model):
    """Model to store device tokens for push notifications"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='device_tokens')
    device_token = models.CharField(max_length=255)
    device_type = models.CharField(max_length=20, default='web')  # web, android, ios
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('user', 'device_token')
        verbose_name = 'User Device Token'
        verbose_name_plural = 'User Device Tokens'

    def __str__(self):
        return f"{self.user.username} - {self.device_type} ({self.device_token[:10]}...)"
    
class ConfigAuditLog(models.Model):
    """Model to track configuration changes for audit purposes"""
    CHANGE_TYPES = (
        ('apache_path', 'Apache Log Path'),
        ('mysql_path', 'MySQL Log Path'),
        ('system_path', 'System Log Path'),
        ('custom_path', 'Custom Log Path'),
        ('setting', 'System Setting'),
    )
    
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('reverted', 'Reverted'),
    )
    
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    change_type = models.CharField(max_length=30, choices=CHANGE_TYPES)
    previous_value = models.TextField(null=True, blank=True) 
    new_value = models.TextField()
    description = models.TextField()
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    reverted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reverted_changes')
    reverted_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        
    def __str__(self):
        return f"{self.change_type} changed by {self.user} on {self.timestamp.strftime('%Y-%m-%d %H:%M')}"
