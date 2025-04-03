from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils.decorators import method_decorator
from django.views.generic import ListView, DetailView, UpdateView
from django.urls import reverse_lazy
from django.utils import timezone
from django.db import models
import json

from .models import DetectionRule, Threat, Incident, BlacklistedIP
from .forms import DetectionRuleForm, ThreatUpdateForm, IncidentForm

@login_required
def dashboard(request):
    """Threat detection dashboard"""
    # Get recent threats and incidents
    recent_threats = Threat.objects.all().order_by('-created_at')[:10]
    open_incidents = Incident.objects.filter(
        status__in=['open', 'investigating']
    ).order_by('-updated_at')[:5]
    
    # Count by severity
    threat_counts = {
        'critical': Threat.objects.filter(severity='critical').count(),
        'high': Threat.objects.filter(severity='high').count(),
        'medium': Threat.objects.filter(severity='medium').count(),
        'low': Threat.objects.filter(severity='low').count(),
    }
    
    # Get stats for today
    today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    today_threats = Threat.objects.filter(created_at__gte=today_start).count()
    today_incidents = Incident.objects.filter(created_at__gte=today_start).count()
    
    # Top affected IPs
    top_ips = Threat.objects.values('source_ip').exclude(
        source_ip__isnull=True
    ).annotate(
        count=models.Count('id')
    ).order_by('-count')[:5]
    
    context = {
        'recent_threats': recent_threats,
        'open_incidents': open_incidents,
        'threat_counts': threat_counts,
        'today_threats': today_threats,
        'today_incidents': today_incidents,
        'top_ips': top_ips,
        'active_blacklists': BlacklistedIP.objects.filter(active=True).count(),
        'title': 'Threat Detection'
    }
    
    return render(request, 'threat_detection/dashboard.html', context)

@method_decorator(login_required, name='dispatch')
class RuleListView(ListView):
    model = DetectionRule
    template_name = 'threat_detection/rules_list.html'
    context_object_name = 'rules'
    
    def get_queryset(self):
        return DetectionRule.objects.all().order_by('rule_type', 'name')

@login_required
def rule_detail(request, pk):
    rule = get_object_or_404(DetectionRule, pk=pk)
    
    # Get recent threats detected by this rule
    recent_threats = Threat.objects.filter(rule=rule).order_by('-created_at')[:20]
    
    context = {
        'rule': rule,
        'recent_threats': recent_threats,
        'title': f'Rule: {rule.name}'
    }
    
    return render(request, 'threat_detection/rule_detail.html', context)

@login_required
def add_rule(request):
    if request.method == 'POST':
        form = DetectionRuleForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Rule added successfully.')
            return redirect('rule_list')
    else:
        form = DetectionRuleForm()
    
    return render(request, 'threat_detection/rule_form.html', {
        'form': form,
        'title': 'Add Rule'
    })

@login_required
def edit_rule(request, pk):
    rule = get_object_or_404(DetectionRule, pk=pk)
    
    if request.method == 'POST':
        form = DetectionRuleForm(request.POST, instance=rule)
        if form.is_valid():
            form.save()
            messages.success(request, 'Rule updated successfully.')
            return redirect('rule_detail', pk=rule.pk)
    else:
        form = DetectionRuleForm(instance=rule)
    
    return render(request, 'threat_detection/rule_form.html', {
        'form': form,
        'rule': rule,
        'title': f'Edit Rule: {rule.name}'
    })

@method_decorator(login_required, name='dispatch')
class ThreatListView(ListView):
    model = Threat
    template_name = 'threat_detection/threats_list.html'
    context_object_name = 'threats'
    paginate_by = 50
    
    def get_queryset(self):
        queryset = Threat.objects.all().order_by('-created_at')
        
        # Apply filters
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)
            
        severity = self.request.GET.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
            
        return queryset

@login_required
def threat_detail(request, pk):
    threat = get_object_or_404(Threat, pk=pk)
    
    if request.method == 'POST':
        form = ThreatUpdateForm(request.POST, instance=threat)
        if form.is_valid():
            form.save()
            messages.success(request, 'Threat updated successfully.')
            return redirect('threat_detail', pk=threat.pk)
    else:
        form = ThreatUpdateForm(instance=threat)
    
    # Get the parsed log data
    parsed_log = threat.parsed_log
    
    # Get incidents this threat is part of
    incidents = threat.incidents.all()
    
    # Get other threats from the same source
    related_threats = []
    if threat.source_ip:
        related_threats = Threat.objects.filter(
            source_ip=threat.source_ip
        ).exclude(id=threat.id).order_by('-created_at')[:10]
    
    context = {
        'threat': threat,
        'form': form,
        'parsed_log': parsed_log,
        'incidents': incidents,
        'related_threats': related_threats,
        'title': f'Threat: {threat.rule.name}'
    }
    
    return render(request, 'threat_detection/threat_detail.html', context)

@method_decorator(login_required, name='dispatch')
class IncidentListView(ListView):
    model = Incident
    template_name = 'threat_detection/incidents_list.html'
    context_object_name = 'incidents'
    paginate_by = 20
    
    def get_queryset(self):
        queryset = Incident.objects.all().order_by('-created_at')
        
        # Apply filters
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)
            
        severity = self.request.GET.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
            
        return queryset

@login_required
def incident_detail(request, pk):
    incident = get_object_or_404(Incident, pk=pk)
    
    if request.method == 'POST':
        form = IncidentForm(request.POST, instance=incident)
        if form.is_valid():
            form.save()
            messages.success(request, 'Incident updated successfully.')
            return redirect('incident_detail', pk=incident.pk)
    else:
        form = IncidentForm(instance=incident)
    
    context = {
        'incident': incident,
        'form': form,
        'title': f'Incident: {incident.id}'
    }
    
    return render(request, 'threat_detection/incident_detail.html', context)

@login_required
def blacklisted_ips(request):
    """View for managing blacklisted IPs"""
    blacklisted = BlacklistedIP.objects.all().order_by('-created_at')
    
    context = {
        'blacklisted': blacklisted,
        'title': 'Blacklisted IPs'
    }
    
    return render(request, 'threat_detection/blacklisted_ips.html', context)

@login_required
def add_to_blacklist(request, ip_address=None):
    """Add an IP to the blacklist"""
    if request.method == 'POST':
        ip = request.POST.get('ip_address', ip_address)
        reason = request.POST.get('reason', 'Manually blacklisted')
        
        if ip:
            try:
                blacklist, created = BlacklistedIP.objects.get_or_create(
                    ip_address=ip,
                    defaults={
                        'reason': reason,
                        'added_by': request.user,
                        'active': True
                    }
                )
                
                if not created:
                    blacklist.active = True
                    blacklist.reason = reason
                    blacklist.save()
                    
                messages.success(request, f'IP {ip} has been blacklisted.')
            except Exception as e:
                messages.error
                messages.success(request, f'IP {ip} has been blacklisted.')
            except Exception as e:
                messages.error(request, f'Error blacklisting IP: {str(e)}')
        else:
            messages.error(request, 'No IP address provided.')
            
        # Redirect back to referring page or blacklist page
        return redirect(request.META.get('HTTP_REFERER', 'blacklisted_ips'))
        
    # If GET request, show the form
    return render(request, 'threat_detection/add_to_blacklist.html', {
        'ip_address': ip_address,
        'title': 'Add to Blacklist'
    })
