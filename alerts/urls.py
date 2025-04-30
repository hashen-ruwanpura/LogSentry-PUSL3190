from django.urls import path
from . import views

urlpatterns = [
    path('notifications/', views.notifications_view, name='notifications'),
    path('notification-preferences/', views.notification_preferences, name='notification_preferences'),
    path('smtp-settings/', views.smtp_settings_view, name='smtp_settings'),
    path('api/test-smtp/', views.test_smtp_settings, name='test_smtp'),
    
    # Consolidated notification API endpoints
    path('api/notifications/', views.api_notifications, name='api_notifications'),
    path('api/notifications/<int:notification_id>/read/', views.api_mark_notification_read, name='api_mark_notification_read'),
    path('api/notifications/mark-all-read/', views.api_mark_all_read, name='api_mark_all_read'),
]