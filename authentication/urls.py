from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from . import views_reports
from .reset_views import CustomPasswordResetConfirmView  # Import the custom view
from . import views_settings
from . import views_admin_contact

urlpatterns = [
    # ... existing URL patterns ...
    
    # API endpoints
    path('api/alerts/<int:alert_id>/', views.alert_detail_api, name='alert_detail_api'),
    path('api/alerts/<int:alert_id>/analyze/', views.analyze_alert_with_ai, name='analyze_alert'),
    path('dashboard-data-api/', views.dashboard_data_api, name='dashboard_data_api'),
    path('api/reports/geo-attacks/', views_reports.geo_attacks_data, name='geo_attacks_data'),
    path('api/server-status/', views.server_status_api, name='server_status_api'),
    
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
        
    # Settings URLs
    path('settings/', views_settings.settings_view, name='settings'),
    path('settings/update-profile/', views_settings.update_profile, name='update_profile'),
    path('settings/save-log-settings/', views_settings.save_log_settings, name='save_log_settings'),
    path('settings/change-password/', views_settings.change_password, name='change_password'),
    path('settings/save-notification-settings/', views_settings.save_notification_settings, name='save_notification_settings'),
    
    # API endpoints for settings
    path('api/test-log-paths/', views_settings.test_log_paths, name='test_log_paths'),
    path('api/analyze-logs/', views_settings.analyze_logs_api, name='analyze_logs'),
    path('api/start-real-time-analysis/', views_settings.start_real_time_analysis, name='start_real_time_analysis'),
    path('api/debug-log-sources/', views_settings.debug_log_sources, name='debug_log_sources'),
    path('api/clean-log-sources/', views_settings.clean_log_sources, name='clean_log_sources'),

    # Admin user support URLs
    path('admin-panel/user-support/', views_admin_contact.admin_user_support, name='admin_user_support'),
    path('api/admin/messages/<int:message_id>/', views_admin_contact.message_detail, name='message_detail_api'),
    path('api/admin/messages/<int:message_id>/reply/', views_admin_contact.reply_to_message, name='reply_to_message'),
    path('api/admin/messages/<int:message_id>/mark-read/', views_admin_contact.mark_message_read, name='mark_message_read'),
    path('api/admin/messages/<int:message_id>/mark-unread/', views_admin_contact.mark_message_unread, name='mark_message_unread'),
    path('api/admin/messages/<int:message_id>/delete/', views_admin_contact.delete_message, name='delete_message'),
    path('api/admin/message-stats/', views_admin_contact.contact_message_stats, name='contact_message_stats'),

    # Contact form submission URL
    path('submit-contact/', views.submit_contact, name='submit_contact'),
]
