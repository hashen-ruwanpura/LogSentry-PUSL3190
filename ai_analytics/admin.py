from django.contrib import admin
from .models import AIReport, AIReportFeedback

@admin.register(AIReport)
class AIReportAdmin(admin.ModelAdmin):
    list_display = ('title', 'report_type', 'generated_at', 'created_by')
    list_filter = ('report_type', 'generated_at', 'source_filter', 'severity_filter')
    search_fields = ('title', 'content')
    date_hierarchy = 'generated_at'
    readonly_fields = ('generated_at', 'tokens_used')
    
    fieldsets = (
        ('Report Information', {
            'fields': ('title', 'report_type', 'content', 'generated_at')
        }),
        ('Time Period', {
            'fields': ('time_period_start', 'time_period_end')
        }),
        ('Filters', {
            'fields': ('source_filter', 'severity_filter')
        }),
        ('Metadata', {
            'fields': ('created_by', 'tokens_used', 'is_cached', 'cache_valid_until')
        })
    )

@admin.register(AIReportFeedback)
class AIReportFeedbackAdmin(admin.ModelAdmin):
    # Use submitted_at field name to match the database schema
    list_display = ('report', 'user', 'rating', 'submitted_at')
    list_filter = ('rating', 'submitted_at')
    date_hierarchy = 'submitted_at'
    search_fields = ('comments', 'user__username', 'report__title')
    
    fieldsets = (
        ('Feedback', {
            'fields': ('report', 'user', 'rating')
        }),
        ('Details', {
            'fields': ('comments', 'submitted_at')
        })
    )
    
    readonly_fields = ('submitted_at',)
