from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from . import views_reports
from .reset_views import CustomPasswordResetConfirmView  # Import the custom view
from . import views_settings

urlpatterns = [
    # ... existing URL patterns ...
    
    # API endpoints
    path('api/alerts/<int:alert_id>/', views.alert_detail_api, name='alert_detail_api'),
    path('api/alerts/<int:alert_id>/analyze/', views.analyze_alert_with_ai, name='analyze_alert'),
    path('dashboard-data-api/', views.dashboard_data_api, name='dashboard_data_api'),
    path('api/reports/geo-attacks/', views_reports.geo_attacks_data, name='geo_attacks_data'),
    
    # Password reset - using custom view for confirmation
    path('password-reset/', 
         auth_views.PasswordResetView.as_view(
             template_name='reset_password.html',
             email_template_name='registration/password_reset_email.html',
             subject_template_name='registration/password_reset_subject.txt',
             success_url='/password-reset-done/'
         ), 
         name='password_reset'),
    
    path('password-reset-done/', 
         auth_views.PasswordResetDoneView.as_view(
             template_name='reset_password.html',
             extra_context={'password_reset_done': True}
         ), 
         name='password_reset_done'),
    
    # Use the custom view for password reset confirmation
    path('password-reset-confirm/<uidb64>/<token>/', 
         CustomPasswordResetConfirmView.as_view(
             template_name='reset_password.html',
             success_url='/password-reset-complete/'
         ), 
         name='password_reset_confirm'),
    
    path('password-reset-complete/', 
         auth_views.PasswordResetCompleteView.as_view(
             template_name='reset_password.html',
             extra_context={'password_reset_complete': True}
         ), 
         name='password_reset_complete'),
    
        
    path('settings/', views.settings_view, name='settings'),
    
    # New API endpoints
    path('api/test-log-paths/', views_settings.test_log_paths, name='test_log_paths'),
    path('api/validate-file-path/', views_settings.validate_file_path, name='validate_file_path'),
    path('api/analyze-logs/', views_settings.analyze_logs_api, name='analyze_logs'),
    path('api/run-analysis-now/', views_settings.run_analysis_now, name='run_analysis_now'),
    path('api/toggle-analysis/', views_settings.toggle_analysis, name='toggle_analysis'),
    path('api/analysis-status/', views_settings.get_analysis_status, name='analysis_status'),
    path('api/force-analyze-logs/', views_settings.force_analyze_all_logs, name='force_analyze_logs'),
    path('api/generate-test-logs/', views_settings.generate_test_logs, name='generate_test_logs'),
    path('api/debug-log-status/', views_settings.debug_log_status, name='debug_log_status'),
    path('api/import-threat-test-logs/', views_settings.import_threat_test_logs, name='import_threat_test_logs'),
    
    path('api/dashboard-data/', views.dashboard_data_api, name='dashboard_data_api'),
    path('api/profile-stats/', views.profile_stats_api, name='profile_stats_api'),
    
    # Add to your urls.py file
    path('api/events/<int:event_id>/', views.api_event_detail, name='api_event_detail'),
    path('api/events/<int:event_id>/resolve/', views.api_resolve_event, name='api_resolve_event'),
]
