from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from . import views_reports
from .reset_views import CustomPasswordResetConfirmView  # Import the custom view

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
    path('api/test-log-paths/', views.test_log_paths, name='test_log_paths'),
    path('api/analyze-logs/', views.analyze_logs_api, name='analyze_logs'),
    
    path('api/dashboard-data/', views.dashboard_data_api, name='dashboard_data_api'),
    path('api/profile-stats/', views.profile_stats_api, name='profile_stats_api'),
    
    # Add to your urls.py file
    path('api/events/<int:event_id>/', views.api_event_detail, name='api_event_detail'),
    path('api/events/<int:event_id>/resolve/', views.api_resolve_event, name='api_resolve_event'),
]
