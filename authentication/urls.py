from django.urls import path
from . import views
from . import views_reports

urlpatterns = [
    # ... existing url patterns ...
    
    # Add these API endpoints
    path('api/alerts/<int:alert_id>/', views.alert_detail_api, name='alert_detail_api'),
    path('api/alerts/<int:alert_id>/analyze/', views.analyze_alert_with_ai, name='analyze_alert'),
    path('dashboard-data-api/', views.dashboard_data_api, name='dashboard_data_api'),
    
    path('api/reports/geo-attacks/', views_reports.geo_attacks_data, name='geo_attacks_data'),
]
