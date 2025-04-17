from django.contrib import admin
from .models import DetectionRule, Threat, Incident, BlacklistedIP

@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = ['name', 'rule_type', 'severity', 'enabled']  # Changed 'active' to 'enabled' and removed 'created_at'
    list_filter = ['severity', 'rule_type', 'enabled']  # Changed 'active' to 'enabled'
    search_fields = ['name', 'description', 'pattern']

@admin.register(Threat)
class ThreatAdmin(admin.ModelAdmin):
    list_display = ['id', 'rule', 'severity', 'status', 'source_ip', 'created_at']
    list_filter = ['severity', 'status', 'created_at']
    search_fields = ['description', 'source_ip', 'user_id']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = [
        ('Basic Information', {
            'fields': ['rule', 'severity', 'status', 'description']
        }),
        ('Source Details', {
            'fields': ['source_ip', 'user_id', 'affected_system']
        }),
        ('MITRE ATT&CK', {
            'fields': ['mitre_technique', 'mitre_tactic']
        }),
        ('Analysis', {
            'fields': ['analysis_data', 'recommendation']
        }),
        ('Timestamps', {
            'fields': ['created_at', 'updated_at']
        }),
    ]

@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ('name', 'severity', 'status', 'start_time', 'end_time')
    list_filter = ('severity', 'status')
    search_fields = ('name', 'description', 'affected_ips')
    filter_horizontal = ('threats',)

@admin.register(BlacklistedIP)
class BlacklistedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'active', 'created_at', 'expires_at')
    list_filter = ('active',)
    search_fields = ('ip_address', 'reason')
