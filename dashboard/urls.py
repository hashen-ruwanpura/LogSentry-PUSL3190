from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ThreatViewSet, IncidentViewSet, LogViewSet

router = DefaultRouter()
router.register(r'threats', ThreatViewSet)
router.register(r'incidents', IncidentViewSet)
router.register(r'logs', LogViewSet)

urlpatterns = [
    path('', include(router.urls)),
]