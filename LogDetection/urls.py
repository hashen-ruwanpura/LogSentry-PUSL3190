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
from django.urls import path, include
from django.conf import settings  # Add this import
from django.conf.urls.static import static  # Add this import if not already present
from django.contrib.auth import views as auth_views
from authentication.views import signup_view
from .views import home  # Import the home view
from authentication import views
from authentication.views import signup_view, CustomLoginView, admin_home
from authentication import views_admin
from authentication import views_admin_logs
from authentication import views_admin_alerts
from authentication import views_admin_settings
from analytics import views as analytics_views
from django.shortcuts import redirect
from authentication import views_admin
from authentication import views_reports  # Import the new views

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

    path('events/', views.events_view, name='events'),
    path('events/export/', views.export_events, name='export_events'),
    path('apache-logs/', views.apache_logs_view, name='apache_logs'),
    path('mysql-logs/', views.mysql_logs_view, name='mysql_logs'),
    path('reports/', views.reports_view, name='reports'),
    path('settings/', views.settings_view, name='settings'),
    path('explore-agent/', views.explore_agent_view, name='explore_agent'),
    path('generate-report/', views.generate_report_view, name='generate_report'),
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
    
    path('', home),  # Add this line to handle the root URL

    # User Reports View
    path('reports/', views_reports.reports_view, name='reports'),
    # Reports API Endpoints
    path('api/reports/dashboard/', views_reports.reports_dashboard_data, name='reports_dashboard_data'),
    path('api/reports/threat-trend/', views_reports.threat_trend_data, name='threat_trend_data'),
    path('api/reports/threat-details/<int:threat_id>/', views_reports.threat_details, name='threat_details'),
    path('api/reports/export/', views_reports.export_report, name='export_report'),
    path('api/reports/export-table/', views_reports.export_table_data, name='export_table_data'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)