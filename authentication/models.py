from django.db import models
from django.contrib.auth.models import User
import json
from django.utils import timezone
from django.core.serializers.json import DjangoJSONEncoder

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
