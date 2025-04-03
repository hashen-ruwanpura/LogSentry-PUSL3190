from django.urls import path
from . import views

urlpatterns = [
    path('sources/', views.log_sources_list, name='log_sources_list'),
    path('sources/add/', views.add_log_source, name='add_log_source'),
    path('sources/edit/<int:pk>/', views.edit_log_source, name='edit_log_source'),
    path('sources/toggle/<int:pk>/', views.toggle_log_source, name='toggle_log_source'),
    path('collection/start/', views.start_log_collection, name='start_log_collection'),
    path('collection/stop/', views.stop_log_collection, name='stop_log_collection'),
    path('raw-logs/', views.RawLogListView.as_view(), name='raw_logs_list'),
    path('parsed-logs/', views.ParsedLogListView.as_view(), name='parsed_logs_list'),
    path('parsed-logs/<int:pk>/', views.ParsedLogDetailView.as_view(), name='parsed_log_detail'),
]