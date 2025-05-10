import json
import os
from datetime import datetime, timedelta
from django.utils import timezone
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from log_ingestion.models import RawLog, ParsedLog
from threat_detection.models import Threat, BlacklistedIP
from threat_detection.models import Threat, ThreatAnalysis
from django.core.mail import send_mail
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import user_passes_test
from django.conf import settings
from django.utils import timezone
from datetime import datetime, timedelta
from log_ingestion.models import LogSource, RawLog, ParsedLog  # Remove LogEntry
from threat_detection.models import Threat
from django.db.models import Count, Q
import logging
from django.views.decorators.http import require_POST
from django.http import HttpResponse, JsonResponse
import io
import csv
from django.contrib.auth.views import LoginView
from django.urls import reverse_lazy, reverse
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth import update_session_auth_hash

from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.units import inch
from io import BytesIO
from django.db.models import Count, Sum
from django.conf import settings

from threat_detection.models import Threat, ThreatAnalysis
from ai_analytics.services import AlertAnalysisService
from alerts.models import NotificationPreference
from .models import ContactMessage, AdminReply, User
from log_ingestion.predictive_maintenance import predict_resource_exhaustion, predict_all_agents
import traceback

# Configure logger
logger = logging.getLogger(__name__)

@login_required
def explore_agent_view(request):
    """
    View for exploring log collection agent information and status.
    Shows agent health, configuration, and recent activities.
    """
    # Get filter parameters
    status = request.GET.get('status', 'all')
    agent_type = request.GET.get('type', 'all')
    search_query = request.GET.get('search', '')
    page = int(request.GET.get('page', 1))
    
    # Base queryset - assuming you have an Agent model
    # If you don't have this model, you'll need to adjust this accordingly
    try:
        from log_ingestion.models import LogAgent
        agents = LogAgent.objects.all()
        
        # Apply filters
        if status != 'all':
            agents = agents.filter(status=status)
        
        if agent_type != 'all':
            agents = agents.filter(agent_type=agent_type)
        
        if search_query:
            agents = agents.filter(
                Q(name__icontains=search_query) |
                Q(hostname__icontains=search_query) |
                Q(ip_address__icontains=search_query)
            )
        
        # Get status counts for filters
        active_count = LogAgent.objects.filter(status='active').count()
        inactive_count = LogAgent.objects.filter(status='inactive').count()
        error_count = LogAgent.objects.filter(status='error').count()
        
        # Get agent types for filters
        agent_types = LogAgent.objects.values_list('agent_type', flat=True).distinct()
        
        # Pagination
        per_page = 20
        paginator = Paginator(agents, per_page)
        
        try:
            agents_page = paginator.page(page)
        except (EmptyPage, PageNotAnInteger):
            agents_page = paginator.page(1)
            page = 1
        
        # Get predictions for active agents on the current page only
        predictions = {}
        for agent in agents_page:
            if agent.status == 'active':
                try:
                    # Only get prediction if the agent is active
                    prediction = predict_resource_exhaustion(agent.id)
                    predictions[agent.id] = prediction
                except Exception as e:
                    logger.error(f"Failed to get prediction for agent {agent.id}: {str(e)}")
                    predictions[agent.id] = {'error': str(e)}
        
        context = {
            'agents': agents_page,
            'total_agents': agents.count(),
            'active_count': active_count,
            'inactive_count': inactive_count,
            'error_count': error_count,
            'agent_types': agent_types,
            'current_status': status,
            'current_type': agent_type,
            'search_query': search_query,
            'current_page': page,
            'total_pages': paginator.num_pages,
            'page_range': paginator.get_elided_page_range(page, on_each_side=2, on_ends=1),
            'predictions': predictions,  # Add predictions to context
        }
    except ImportError:
        # Fallback if LogAgent model doesn't exist
        context = {
            'error_message': "Agent monitoring is not available. The LogAgent model is not defined.",
            'agents': [],
            'total_agents': 0,
        }
    except Exception as e:
        # General error handling
        context = {
            'error_message': f"An error occurred while loading agent data: {str(e)}",
            'agents': [],
            'total_agents': 0,
        }
        
    return render(request, 'authentication/explore_agent.html', context)

@login_required
def agent_prediction_api(request, agent_id=None):
    """API endpoint for resource exhaustion predictions"""
    try:
        # Get time window from request, default to 24 hours
        time_window = int(request.GET.get('time_window', 24))
        
        # If agent_id is provided, get prediction for that agent only
        if agent_id:
            prediction = predict_resource_exhaustion(agent_id, time_window)
            return JsonResponse(prediction)
        else:
            # Get predictions for all agents
            batch = request.GET.get('batch', 'false').lower() == 'true'
            
            if batch:
                predictions = predict_all_agents(time_window)
                return JsonResponse({'predictions': predictions})
            else:
                # If no agent_id and not batch, return error
                return JsonResponse({'error': 'No agent_id provided. Use batch=true for all agents.'}, status=400)
    
    except Exception as e:
        import traceback
        logger.exception(f"Error in agent prediction API: {str(e)}")
        return JsonResponse({
            'error': str(e),
            'traceback': traceback.format_exc()
        }, status=500)