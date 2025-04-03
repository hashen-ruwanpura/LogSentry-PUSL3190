from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils.decorators import method_decorator
from django.views.generic import ListView, DetailView, CreateView, UpdateView
from django.urls import reverse_lazy
from .models import LogSource, RawLog, ParsedLog
from .forms import LogSourceForm
from .collectors import log_manager

@login_required
def log_sources_list(request):
    """List all log sources and their status"""
    sources = LogSource.objects.all().order_by('name')
    
    context = {
        'sources': sources,
        'title': 'Log Sources'
    }
    return render(request, 'log_ingestion/sources_list.html', context)

@login_required
def add_log_source(request):
    """Add a new log source"""
    if request.method == 'POST':
        form = LogSourceForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Log source added successfully.')
            return redirect('log_sources_list')
    else:
        form = LogSourceForm()
    
    context = {
        'form': form,
        'title': 'Add Log Source'
    }
    return render(request, 'log_ingestion/source_form.html', context)

@login_required
def edit_log_source(request, pk):
    """Edit an existing log source"""
    source = get_object_or_404(LogSource, pk=pk)
    
    if request.method == 'POST':
        form = LogSourceForm(request.POST, instance=source)
        if form.is_valid():
            form.save()
            messages.success(request, 'Log source updated successfully.')
            return redirect('log_sources_list')
    else:
        form = LogSourceForm(instance=source)
    
    context = {
        'form': form,
        'title': 'Edit Log Source'
    }
    return render(request, 'log_ingestion/source_form.html', context)

@login_required
def toggle_log_source(request, pk):
    """Enable or disable a log source"""
    source = get_object_or_404(LogSource, pk=pk)
    source.enabled = not source.enabled
    source.save()
    
    status = 'enabled' if source.enabled else 'disabled'
    messages.success(request, f'Log source {source.name} {status} successfully.')
    
    # Reload log sources if we enabled one
    if source.enabled:
        log_manager.reload_sources()
    
    return redirect('log_sources_list')

@login_required
def start_log_collection(request):
    """Start the log collection process"""
    success = log_manager.start_monitoring()
    
    if success:
        messages.success(request, 'Log collection started successfully.')
    else:
        messages.error(request, 'Log collection is already running or failed to start.')
    
    return redirect('log_sources_list')

@login_required
def stop_log_collection(request):
    """Stop the log collection process"""
    success = log_manager.stop_monitoring()
    
    if success:
        messages.success(request, 'Log collection stopped successfully.')
    else:
        messages.error(request, 'Log collection is not running or failed to stop.')
    
    return redirect('log_sources_list')

@method_decorator(login_required, name='dispatch')
class RawLogListView(ListView):
    model = RawLog
    template_name = 'log_ingestion/raw_logs_list.html'
    context_object_name = 'logs'
    paginate_by = 100
    ordering = ['-timestamp']
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Apply filters from GET parameters
        source_id = self.request.GET.get('source')
        if source_id:
            queryset = queryset.filter(source_id=source_id)
            
        is_parsed = self.request.GET.get('parsed')
        if is_parsed:
            queryset = queryset.filter(is_parsed=(is_parsed == '1'))
            
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['sources'] = LogSource.objects.all()
        context['title'] = 'Raw Logs'
        return context

@method_decorator(login_required, name='dispatch')
class ParsedLogListView(ListView):
    model = ParsedLog
    template_name = 'log_ingestion/parsed_logs_list.html'
    context_object_name = 'logs'
    paginate_by = 100
    ordering = ['-timestamp']
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Apply filters from GET parameters
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(status=status)
            
        source_ip = self.request.GET.get('ip')
        if source_ip:
            queryset = queryset.filter(source_ip=source_ip)
            
        log_level = self.request.GET.get('level')
        if log_level:
            queryset = queryset.filter(log_level=log_level)
            
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Parsed Logs'
        return context

@method_decorator(login_required, name='dispatch')
class ParsedLogDetailView(DetailView):
    model = ParsedLog
    template_name = 'log_ingestion/parsed_log_detail.html'
    context_object_name = 'log'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Log Details'
        
        # Add context for related logs from the same IP
        log = self.get_object()
        if log.source_ip:
            related_logs = ParsedLog.objects.filter(
                source_ip=log.source_ip
            ).exclude(id=log.id).order_by('-timestamp')[:10]
            context['related_logs'] = related_logs
            
        return context
