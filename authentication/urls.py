from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from . import views_reports
from .reset_views import CustomPasswordResetConfirmView  # Import the custom view
from . import views_settings
from . import views_admin_contact
from . import views_apache_logs
from .views_apache_logs import apache_logs_view, apache_logs_api
from .views_mysql_logs import mysql_logs_view, mysql_logs_api
from . import views_explore_agent
from .views_predictive import predictive_maintenance_view, resource_predictions_api, system_metrics_api, automated_tasks_api
from authentication import views_predictive
from . import notification_views
from alerts import notification_api  # Import from alerts app instead

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
    
    # Apache logs URLs
    path('apache-logs/', apache_logs_view, name='apache_logs'),
    path('api/apache-logs/', apache_logs_api, name='apache_logs_api'),

    # MySQL logs URLs
    path('mysql-logs/', mysql_logs_view, name='mysql_logs'),
    path('api/mysql-logs/', mysql_logs_api, name='mysql_logs_api'),

    # Agent prediction API
    path('api/agent-prediction/<int:agent_id>/', views_explore_agent.agent_prediction_api, name='agent_prediction_api'),
    path('api/agent-prediction/', views_explore_agent.agent_prediction_api, name='agent_prediction_api_batch'),

    # Predictive maintenance URLs
    path('predictive-maintenance/', predictive_maintenance_view, name='predictive_maintenance'),
    path('api/resource-predictions/', resource_predictions_api, name='resource_predictions_api'),
    path('api/system-metrics/', system_metrics_api, name='system_metrics_api'),
    path('api/automated-tasks/', automated_tasks_api, name='automated_tasks_api'),
    path('api/open-folder/', views_predictive.open_folder, name='open_folder'),

    # Device registration URLs
    path('api/auth/register-device/', notification_views.register_device, name='register_device'),
    path('api/auth/unregister-device/', notification_views.unregister_device, name='unregister_device'),

]
