from django.urls import path
from . import views
from . import notification_api
from authentication import notification_views

urlpatterns = [
    # Regular HTTP endpoints
    path('', views.alerts_list, name='alerts_list'),
    path('<int:alert_id>/', views.alert_detail, name='alert_detail'),
    
    # Notification API endpoints
    path('api/notifications/', notification_api.get_notifications, name='get_notifications'),
    path('api/notifications/<int:notification_id>/read/', notification_api.mark_notification_read, name='mark_notification_read'),
    path('api/notifications/mark-all-read/', notification_api.mark_all_read, name='mark_all_read'),
    path('api/notifications/recent/', notification_api.recent_notifications, name='recent_notifications'),
]