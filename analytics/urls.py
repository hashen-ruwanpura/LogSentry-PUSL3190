from django.urls import path
from . import views

urlpatterns = [
    path('simple-dashboard', views.simple_dashboard_data, name='api_simple_dashboard_data'),
    path('simple-dashboard/', views.simple_dashboard_data, name='api_simple_dashboard_data_slash'),
    path('dashboard', views.dashboard_data, name='api_dashboard_data'),
    path('threat-trend', views.threat_trend_data, name='api_threat_trend'),
    path('threat-details/<int:threat_id>', views.threat_detail, name='api_threat_detail'),
    path('resolve-threat/<int:threat_id>', views.resolve_threat, name='api_resolve_threat'),
    path('export', views.export_reports, name='api_export_reports'),
    path('debug', views.debug_reports, name='api_debug_reports'),
]