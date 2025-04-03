from django.contrib import admin
from .models import DetectionRule, Threat, Incident, BlacklistedIP

@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = ('name', 'rule_type', 'severity', 'active', 'created_at')
    list_filter = ('rule_type', 'severity', 'active')
    search_fields = ('name', 'description')

@admin.register(Threat)
class ThreatAdmin(admin.ModelAdmin):
    list_display = ('rule', 'source_ip', 'severity', 'status', 'created_at')
    list_filter = ('severity', 'status', 'rule')
    search_fields = ('source_ip', 'user_id', 'description')
    readonly_fields = ('parsed_log', 'created_at')

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
