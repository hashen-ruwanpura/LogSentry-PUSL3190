from django.shortcuts import render
from rest_framework import viewsets
from .models import Threat, Incident, Log
from .serializers import ThreatSerializer, IncidentSerializer, LogSerializer

class ThreatViewSet(viewsets.ModelViewSet):
    queryset = Threat.objects.all()
    serializer_class = ThreatSerializer

class IncidentViewSet(viewsets.ModelViewSet):
    queryset = Incident.objects.all()
    serializer_class = IncidentSerializer

class LogViewSet(viewsets.ModelViewSet):
    queryset = Log.objects.all()
    serializer_class = LogSerializer

# Create your views here.
