from django.contrib import admin
from .models import LogSource, LogFilePosition, RawLog, ParsedLog

@admin.register(LogSource)
class LogSourceAdmin(admin.ModelAdmin):
    list_display = ('name', 'source_type', 'file_path', 'enabled', 'created_at')
    list_filter = ('source_type', 'enabled')
    search_fields = ('name', 'file_path')

@admin.register(LogFilePosition)
class LogFilePositionAdmin(admin.ModelAdmin):
    list_display = ('source', 'file_path', 'position', 'last_updated')
    list_filter = ('source__source_type',)
    search_fields = ('file_path',)

@admin.register(RawLog)
class RawLogAdmin(admin.ModelAdmin):
    list_display = ('source', 'timestamp', 'is_parsed')
    list_filter = ('source__source_type', 'is_parsed')
    search_fields = ('content',)
    readonly_fields = ('content', 'timestamp', 'is_parsed')

@admin.register(ParsedLog)
class ParsedLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'source_ip', 'status', 'log_level')
    list_filter = ('status', 'log_level')
    search_fields = ('source_ip', 'user_id', 'request_path', 'query')
    readonly_fields = ('raw_log', 'normalized_data')
