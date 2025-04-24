from django.urls import path
from . import views

app_name = 'ai_analytics'

urlpatterns = [
    path('reports/', views.reports_dashboard, name='reports_dashboard'),
    path('reports/<int:report_id>/', views.report_detail, name='report_detail'),
    path('reports/<int:report_id>/json/', views.report_json, name='report_json'),
    path('reports/generate/', views.generate_ai_report, name='generate_report'),
    path('reports/<int:report_id>/feedback/', views.submit_report_feedback, name='submit_feedback'),
    path('reports/list/', views.list_reports, name='list_reports'),
    path('reports/<int:report_id>/delete/', views.delete_report, name='delete_report'),
    path('test-api/', views.test_api, name='test_api'),
]