"""
URL configuration for LogDetection project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings  # Add this import
from django.conf.urls.static import static  # Add this import if not already present
from django.contrib.auth import views as auth_views
from authentication.views import signup_view
from .views import home  # Import the home view
from authentication import views
from authentication import notification_views
from authentication.views import signup_view, CustomLoginView, admin_home, alert_detail  # Updated import
from authentication import views_admin
from authentication import views_admin_logs
from authentication import views_admin_alerts
from authentication import views_admin_settings
from analytics import views as analytics_views
from django.shortcuts import redirect
from alerts import views as alert_views
from alerts import notification_api
from alerts import consumers  # Import the consumers module
from authentication import views_reports  # Import the new views
from authentication import views_settings  # Add this import
from django.views.generic import TemplateView
from authentication.views_apache_logs import apache_logs_view  # Add this import
from authentication.views_mysql_logs import mysql_logs_view  # Add this new import
from authentication import views_explore_agent  # Add this import
from authentication import views_admin_auditlogs  # Add this import
from authentication import views_admin_contact  # Add this import
from authentication.views import profile_stats_api  # Import the profile_stats_api view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('signup/', signup_view, name='signup'),
    path('logout/', auth_views.LogoutView.as_view(
        template_name='registration/logout.html',
        next_page='/',
        http_method_names=['get', 'post']  # This allows GET requests
    ), name='logout'),
    path('profile/', views.profile_view, name='profile'),
    path('contact/', views.contact_view, name='contact'),

    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('explore_logs/', views.explore_logs, name='explore_logs'),
    path('generate_report/', views.generate_report, name='generate_report'),
    path('alert/<int:alert_id>/', views.alert_detail, name='alert_detail'),
    path('', include('authentication.urls')),

    # Add this line to handle the email alert links:
    path('alerts/<int:alert_id>/', alert_detail, name='alert_detail'),

    path('events/', views.events_view, name='events'),
    path('events/export/', views.export_events, name='export_events'),
    path('apache-logs/', apache_logs_view, name='apache_logs'),
    path('mysql-logs/', mysql_logs_view, name='mysql_logs'),
    path('reports/', views.generate_report, name='reports'),
    path('settings/', views_settings.settings_view, name='settings'),  # NEW
    path('explore-agent/', views_explore_agent.explore_agent_view, name='explore_agent'),
    path('generate-report/', views.generate_report, name='generate_report'),
    path('alerts-details/', views.alerts_details_view, name='alerts_details'),
    path('mitre-details/', views.mitre_details_view, name='mitre_details'),
    
    # Add the admin_home URL pattern here
    path('admin-home/', admin_home, name='admin_home'),

    path('admin-panel/users/', views_admin.user_management_view, name='user_management'),
    # Admin log analysis views
    path('admin-panel/logs/', views_admin_logs.logs_view, name='admin_logs'),
    
    # API endpoints for user management
    path('api/users/', views_admin.api_users_list, name='api_users_list'),
    path('api/users/create/', views_admin.api_user_create, name='api_user_create'),
    path('api/users/<int:user_id>/update/', views_admin.api_user_update, name='api_user_update'),
    path('api/users/<int:user_id>/delete/', views_admin.api_user_delete, name='api_user_delete'),

    # API endpoints for log analysis
    path('api/admin/logs/', views_admin_logs.api_logs_list, name='api_admin_logs'),
    path('api/admin/logs/<int:log_id>/', views_admin_logs.api_log_detail, name='api_admin_log_detail'),
    path('api/admin/logs/<int:log_id>/export/', views_admin_logs.api_log_export, name='api_admin_log_export'),

     # Admin alerts views
    path('admin-panel/alerts/', views_admin_alerts.alerts_view, name='admin_alerts'),

    # API endpoints for alert management
    path('api/admin/alerts/', views_admin_alerts.api_alerts_list, name='api_admin_alerts'),
    path('api/admin/alerts/counts/', views_admin_alerts.api_alert_counts, name='api_admin_alert_counts'),
    path('api/admin/alerts/<int:alert_id>/', views_admin_alerts.api_alert_detail, name='api_admin_alert_detail'),
    path('api/admin/alerts/<int:alert_id>/notes/', views_admin_alerts.api_alert_notes, name='api_admin_alert_notes'),
    path('api/admin/alerts/<int:alert_id>/status/', views_admin_alerts.api_alert_status, name='api_admin_alert_status'),
    path('api/admin/alerts/<int:alert_id>/escalate/', views_admin_alerts.api_alert_escalate, name='api_admin_alert_escalate'),
    path('api/admin/alerts/<int:alert_id>/export/', views_admin_alerts.api_alert_export, name='api_admin_alert_export'),

    # Admin settings view
    path('admin-panel/settings/', views_admin_settings.settings_view, name='admin_settings'),

     # API endpoints for settings
    path('api/admin/settings/', views_admin_settings.api_settings_get, name='api_admin_settings'),
    path('api/admin/settings/save/', views_admin_settings.api_settings_save, name='api_admin_settings_save'),
    path('api/admin/settings/reset/', views_admin_settings.api_settings_reset, name='api_admin_settings_reset'),
    path('api/admin/settings/test-email/', views_admin_settings.api_test_email, name='api_admin_test_email'),
    path('api/admin/settings/backup/', views_admin_settings.api_manual_backup, name='api_admin_backup'),

    # user-mangement
    path('api/users/<int:user_id>/', views_admin.api_user_detail, name='api_user_detail'),

    path('admin-panel/reports/', analytics_views.admin_reports_view, name='admin_reports'),
    # Keep the redirect for backward compatibility:
    path('admin-panel/adminreports/', lambda request: redirect('admin_reports'), name='admin_reports_redirect'),
    # Then include the rest of analytics urls
    path('api/admin/reports/', include('analytics.urls')),  # Include analytics URLs

    #admin-dashboard
    path('api/admin/dashboard-data/', views_admin.admin_dashboard_data, name='admin_dashboard_data'),
    path('api/admin/run-log-analysis/', views_admin.run_log_analysis, name='run_log_analysis'),
    path('api/admin/export-report/', views_admin.export_report, name='export_report'),
    
    # Add to your urlpatterns
    path('api/dashboard-data/', views.dashboard_data_api, name='dashboard_data_api'),

    path('', home),  # Add this line to handle the root URL

    # User Reports View
    path('reports/', views_reports.reports_view, name='reports'),
    # Reports API Endpoints
    path('api/reports/dashboard/', views_reports.reports_dashboard_data, name='reports_dashboard_data'),
    path('api/reports/threat-trend/', views_reports.threat_trend_data, name='threat_trend_data'),
    path('api/reports/threat-details/<int:threat_id>/', views_reports.threat_details, name='threat_details'),
    path('api/reports/export/', views_reports.export_report, name='export_report'),
    path('api/reports/export-table/', views_reports.export_table_data, name='export_table_data'),

    # Add the export_events URL pattern here
    path('export_events/', views.export_events, name='export_events'),
    
     # Add these patterns
    path('notifications/<int:notification_id>/read/', alert_views.mark_notification_read, name='mark_notification_read'),
    path('notifications/', notification_views.notifications_view, name='notifications'),
    
    path('api/notifications/', notification_api.get_notifications, name='get_notifications'),
    path('api/notifications/<int:notification_id>/read/', notification_api.mark_notification_read, name='mark_notification_read'),
    path('api/notifications/mark-all-read/', notification_api.mark_all_read, name='mark_all_read'),
    path('api/notifications/recent/', notification_api.recent_notifications, name='recent_notifications'),
    
    # Catch-all for the single-page application

    # Add the notification-test URL pattern here
    path('notification-test/', TemplateView.as_view(template_name='notification_test.html'), name='notification_test'),

    # Add these URL patterns
    path('api/auth/register-device/', notification_api.register_device, name='register_device'),

    # Add the alerts URLs
    path('alerts/', alert_views.alerts_list, name='alerts_list'),

    # Update this pattern to use alert_id instead of threat_id to match the function parameter
    path('alert-detail/<int:alert_id>/', views.alert_detail, name='alert_detail'),

    # Add to the existing urlpatterns list
    path('admin-panel/auditlogs/', views_admin_auditlogs.audit_logs_view, name='admin_audit_logs'),

    # Add these to URL patterns
    path('api/admin/audit-logs/<int:log_id>/revert/', views_admin_auditlogs.revert_config_change, name='api_revert_config'),
    path('api/admin/audit-logs/export/', views_admin_auditlogs.export_audit_logs, name='api_export_audit_logs'),

    # Add this line for message API detail
    path('api/admin/messages/<int:message_id>/', views_admin_contact.message_api_detail, name='message_api_detail'),

    # API endpoint for profile statistics
    path('api/profile-stats/', profile_stats_api, name='profile_stats_api'),
]

# AI ANALYTICS
urlpatterns += [
    path('ai/', include('ai_analytics.urls', namespace='ai_analytics')),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)