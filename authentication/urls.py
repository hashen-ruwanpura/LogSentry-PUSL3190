from django.urls import path
from . import views

urlpatterns = [
    # ... existing url patterns ...
    
    # Add these new API endpoints
    path('api/alerts/<int:alert_id>/', views.alert_detail_api, name='alert_detail_api'),
    path('dashboard-data-api/', views.dashboard_data_api, name='dashboard_data_api'),
]
