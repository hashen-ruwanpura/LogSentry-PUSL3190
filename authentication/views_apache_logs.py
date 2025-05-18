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

@login_required
def apache_logs_view(request):
    """
    View for displaying and analyzing Apache web server logs.
    Provides filtering, search and statistics specific to Apache logs.
    """
    # Get filter parameters
    time_range = request.GET.get('time_range', '24h')
    status_code = request.GET.get('status_code', 'all')
    request_method = request.GET.get('method', 'all')
    search_query = request.GET.get('search', '')
    page = int(request.GET.get('page', 1))
    export_format = request.GET.get('export')  # Get export format parameter
    
    # Determine time period based on selected range
    now = timezone.now()
    if time_range == '1h':
        start_time = now - timedelta(hours=1)
        period_name = 'Last Hour'
    elif time_range == '12h':
        start_time = now - timedelta(hours=12)
        period_name = 'Last 12 Hours'
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
        period_name = 'Last 7 Days'
    elif time_range == '30d':
        start_time = now - timedelta(days=30)
        period_name = 'Last 30 Days'
    else:  # Default to 24h
        start_time = now - timedelta(days=1)
        period_name = 'Last 24 Hours'
        time_range = '24h'
    
    # Base queryset for filtering logs
    logs = ParsedLog.objects.filter(
        Q(raw_log__source__source_type='apache_access') | Q(raw_log__source__source_type='apache'),
        raw_log__timestamp__gte=start_time
    ).select_related('raw_log')
    
    # Apply status code filter
    if status_code != 'all':
        if status_code == '2xx':
            logs = logs.filter(status_code__gte=200, status_code__lt=300)
        elif status_code == '3xx':
            logs = logs.filter(status_code__gte=300, status_code__lt=400)
        elif status_code == '4xx':
            logs = logs.filter(status_code__gte=400, status_code__lt=500)
        elif status_code == '5xx':
            logs = logs.filter(status_code__gte=500)
        else:
            # Try to filter by specific status code
            try:
                logs = logs.filter(status_code=int(status_code))
            except ValueError:
                pass
    
    # Apply request method filter
    if request_method != 'all':
        logs = logs.filter(request_method=request_method)
    
    # Apply search filter if provided
    if search_query:
        logs = logs.filter(
            Q(request_path__icontains=search_query) | 
            Q(source_ip__icontains=search_query) |
            Q(user_agent__icontains=search_query)
        )
    
    # Get the TOTAL count using RawLog to match dashboard
    total_logs = RawLog.objects.filter(
        Q(source__source_type='apache_access') | Q(source__source_type='apache'),
        timestamp__gte=start_time
    ).count()
    
    # Get statistics
    status_2xx = logs.filter(status_code__gte=200, status_code__lt=300).count()
    status_3xx = logs.filter(status_code__gte=300, status_code__lt=400).count()
    status_4xx = logs.filter(status_code__gte=400, status_code__lt=500).count()
    status_5xx = logs.filter(status_code__gte=500).count()
    
    # Get common request methods
    common_methods = logs.values('request_method').annotate(
        count=Count('request_method')
    ).order_by('-count')[:5]
    
    # Get top requested paths
    top_paths = logs.values('request_path').annotate(
        count=Count('request_path')
    ).order_by('-count')[:10]
    
    # Get top source IPs
    top_ips = logs.values('source_ip').annotate(
        count=Count('source_ip')
    ).order_by('-count')[:10]
    
    # Handle PDF export
    if export_format == 'pdf':
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from io import BytesIO
        from django.http import HttpResponse
        
        # Define LogSentry brand colors
        brand_primary = colors.HexColor('#3f51b5')  # Primary blue
        brand_secondary = colors.HexColor('#6c757d')
        brand_light = colors.HexColor('#f5f7fa')
        brand_dark = colors.HexColor('#212529')
        
        # Create response object
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="LogSentry_Apache_Logs_{timezone.now().strftime("%Y%m%d_%H%M")}.pdf"'
        
        # Create PDF document
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(letter), 
                               rightMargin=36, leftMargin=36, 
                               topMargin=36, bottomMargin=36)
        
        # Create custom styles
        styles = getSampleStyleSheet()
        
        # Custom title style
        styles.add(ParagraphStyle(
            name='LogSentryTitle',
            parent=styles['Title'],
            fontName='Helvetica-Bold',
            fontSize=24,
            textColor=brand_primary,
            spaceAfter=12,
            alignment=1  # Center alignment
        ))
        
        # Custom heading styles
        styles.add(ParagraphStyle(
            name='LogSentryHeading1',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=18,
            textColor=brand_primary,
            spaceAfter=12,
        ))
        
        styles.add(ParagraphStyle(
            name='LogSentryHeading2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            textColor=brand_primary,
            spaceAfter=10,
        ))
        
        # Normal text style
        styles.add(ParagraphStyle(
            name='LogSentryNormal',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            spaceAfter=8,
        ))
        
        # Initialize elements list
        elements = []
        
        # Helper function for creating header/footer
        def add_page_elements(canvas, doc):
            # Save canvas state
            canvas.saveState()
            
            # Header with title bar
            canvas.setFillColor(brand_primary)
            canvas.rect(36, doc.height + 36, doc.width, 24, fill=True, stroke=False)
            
            # Header text (LogSentry)
            canvas.setFont('Helvetica-Bold', 14)
            canvas.setFillColor(colors.white)
            canvas.drawString(46, doc.height + doc.topMargin + 6, "LogSentry")
            
            # Add subtitle
            canvas.setFont('Helvetica', 10)
            canvas.drawString(140, doc.height + doc.topMargin + 6, "Apache Web Server Logs")
            
            # Add page number to header
            canvas.drawRightString(doc.width + 20, doc.height + doc.topMargin + 6, f"Page {doc.page}")
            
            # Add footer
            canvas.setFont('Helvetica', 8)
            canvas.setFillColor(brand_secondary)
            
            # Left side: generated date
            generation_text = f"Generated on {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}"
            canvas.drawString(doc.leftMargin, 20, generation_text)
            
            # Right side: powered by
            canvas.drawRightString(doc.width + 30, 20, "Powered by LogSentry")
            
            # Restore canvas state
            canvas.restoreState()
        
        # First page / Cover
        elements.append(Spacer(1, 30))
        
        # Title
        elements.append(Paragraph("Apache Web Server Logs", styles['LogSentryTitle']))
        elements.append(Spacer(1, 10))
        
        # Period and filters subtitle
        report_subtitle = f"{period_name}"
        if status_code != 'all':
            report_subtitle += f" - Status Code: {status_code}"
        if request_method != 'all':
            report_subtitle += f" - Method: {request_method}"
        if search_query:
            report_subtitle += f" - Search: {search_query}"
        
        elements.append(Paragraph(report_subtitle, styles['Heading2']))
        elements.append(Spacer(1, 30))
        
        # Add summary statistics section
        elements.append(Paragraph("Summary Statistics", styles['LogSentryHeading1']))
        elements.append(Spacer(1, 10))
        
        # Create statistics table
        stats_data = [
            ['Metric', 'Value'],
            ['Total Apache Logs', str(total_logs)],
            ['2xx Success', f"{status_2xx} ({status_2xx/max(total_logs, 1)*100:.1f}%)"],
            ['3xx Redirection', f"{status_3xx} ({status_3xx/max(total_logs, 1)*100:.1f}%)"],
            ['4xx Client Error', f"{status_4xx} ({status_4xx/max(total_logs, 1)*100:.1f}%)"],
            ['5xx Server Error', f"{status_5xx} ({status_5xx/max(total_logs, 1)*100:.1f}%)"],
            ['Time Period', period_name]
        ]
        
        stats_table = Table(stats_data, colWidths=[200, 300])
        stats_table.setStyle(TableStyle([
            # Header row styling
            ('BACKGROUND', (0, 0), (-1, 0), brand_primary),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGNMENT', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            
            # Data rows styling
            ('BACKGROUND', (0, 1), (0, -1), colors.HexColor('#f5f7fa')),
            ('TEXTCOLOR', (0, 1), (0, -1), brand_dark),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            
            # Row styling
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        
        elements.append(stats_table)
        elements.append(Spacer(1, 20))
        
        # HTTP Methods section
        elements.append(Paragraph("HTTP Methods", styles['LogSentryHeading2']))
        elements.append(Spacer(1, 5))
        
        # HTTP Methods table
        methods_data = [['Method', 'Count', 'Percentage']]
        total_methods = sum(m['count'] for m in common_methods)
        
        for method in common_methods:
            percentage = method['count'] / max(total_methods, 1) * 100
            methods_data.append([
                method['request_method'], 
                method['count'],
                f"{percentage:.1f}%"
            ])
        
        if len(methods_data) > 1:
            methods_table = Table(methods_data, colWidths=[150, 150, 150])
            methods_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), brand_primary),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGNMENT', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ALIGN', (1, 1), (1, -1), 'RIGHT'),
                ('ALIGN', (2, 1), (2, -1), 'RIGHT'),
            ]))
            elements.append(methods_table)
        else:
            elements.append(Paragraph("No HTTP methods data available", styles['LogSentryNormal']))
            
        elements.append(Spacer(1, 20))
        
        # Top Requested Paths
        elements.append(Paragraph("Top Requested Paths", styles['LogSentryHeading2']))
        elements.append(Spacer(1, 5))
        
        paths_data = [['Path', 'Count']]
        
        for path in top_paths:
            paths_data.append([
                path['request_path'][:80] + ('...' if len(path['request_path']) > 80 else ''),
                path['count']
            ])
        
        if len(paths_data) > 1:
            paths_table = Table(paths_data, colWidths=[400, 100])
            paths_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), brand_primary),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGNMENT', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ALIGN', (1, 1), (1, -1), 'RIGHT'),
            ]))
            elements.append(paths_table)
        else:
            elements.append(Paragraph("No path data available", styles['LogSentryNormal']))
        
        elements.append(Spacer(1, 20))
        
        # Top Source IPs
        elements.append(Paragraph("Top Source IPs", styles['LogSentryHeading2']))
        elements.append(Spacer(1, 5))
        
        ips_data = [['IP Address', 'Count']]
        
        for ip in top_ips:
            ips_data.append([ip['source_ip'], ip['count']])
        
        if len(ips_data) > 1:
            ips_table = Table(ips_data, colWidths=[300, 150])
            ips_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), brand_primary),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGNMENT', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ALIGN', (1, 1), (1, -1), 'RIGHT'),
            ]))
            elements.append(ips_table)
        else:
            elements.append(Paragraph("No IP address data available", styles['LogSentryNormal']))
        
        elements.append(Spacer(1, 30))
        
        # Apache Logs Detail Section
        elements.append(Paragraph("Apache Log Details", styles['LogSentryHeading1']))
        elements.append(Spacer(1, 10))
        
        # Create log records table (limit to 100 for reasonable PDF size)
        logs_data = [['Timestamp', 'Method', 'Path', 'Status', 'IP Address', 'Size']]
        
        # Use the filtered logs but limit to 100 records for PDF
        log_records = logs.order_by('-raw_log__timestamp')[:100]
        
        for log in log_records:
            # Safely handle request_path which might be None
            request_path = log.request_path or '-'
            if len(request_path) > 50:
                request_path = request_path[:50] + '...'
            
            logs_data.append([
                log.raw_log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.request_method or 'UNKNOWN',
                request_path,
                str(log.status_code or '-'),
                log.source_ip or '0.0.0.0',
                str(log.response_size or '-')
            ])
        
        if len(logs_data) > 1:
            # Create table with style
            logs_table = Table(logs_data, colWidths=[100, 60, 220, 50, 100, 50])
            logs_table.setStyle(TableStyle([
                # Header styling
                ('BACKGROUND', (0, 0), (-1, 0), brand_primary),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGNMENT', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                
                # Data styling
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                
                # Alternating row colors
                *[('BACKGROUND', (0, i), (-1, i), colors.HexColor('#f8f9fa'))
                  for i in range(1, len(logs_data)) if i % 2 == 0]
            ]))
            elements.append(logs_table)
        else:
            elements.append(Paragraph("No log records available", styles['LogSentryNormal']))
        
        elements.append(Spacer(1, 20))
        
        # Add note about log count
        if len(log_records) < total_logs:
            elements.append(Paragraph(
                f"Note: This report shows {len(log_records)} of {total_logs} total logs. "
                f"Use filters to see specific logs or export to CSV for a complete dataset.",
                styles['LogSentryNormal']
            ))
        
        # Build PDF document with custom header/footer
        doc.build(elements, onFirstPage=add_page_elements, onLaterPages=add_page_elements)
        
        # Get PDF content
        pdf = buffer.getvalue()
        buffer.close()
        response.write(pdf)
        
        return response
    
    # Pagination
    per_page = 50
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    logs_paginated = logs.order_by('-raw_log__timestamp')[start_idx:end_idx]
    total_pages = (total_logs + per_page - 1) // per_page
    
    # Generate page range
    if total_pages <= 7:
        page_range = range(1, total_pages + 1)
    else:
        if page <= 4:
            page_range = list(range(1, 6)) + ['...', total_pages]
        elif page >= total_pages - 3:
            page_range = [1, '...'] + list(range(total_pages - 4, total_pages + 1))
        else:
            page_range = [1, '...'] + list(range(page - 1, page + 2)) + ['...', total_pages]
    
    # Continue with the original function for normal rendering...
    context = {
        'logs': logs_paginated,
        'total_logs': total_logs,
        'period_name': period_name,
        'time_range': time_range,
        'status_code': status_code,
        'request_method': request_method,
        'search_query': search_query,
        'status_2xx': status_2xx,
        'status_3xx': status_3xx,
        'status_4xx': status_4xx,
        'status_5xx': status_5xx,
        'common_methods': common_methods,
        'top_paths': top_paths,
        'top_ips': top_ips,
        'current_page': page,
        'total_pages': total_pages,
        'page_range': page_range,
        'has_next': page < total_pages,
        'has_prev': page > 1,
        'next_page': page + 1,
        'prev_page': page - 1,
    }
    
    return render(request, 'authentication/apache_logs.html', context)

@login_required
def apache_logs_api(request):
    """API endpoint for fetching Apache logs data via AJAX"""
    # Get filter parameters
    time_range = request.GET.get('time_range', '24h')
    status_code = request.GET.get('status_code', 'all')
    request_method = request.GET.get('method', 'all')
    search_query = request.GET.get('search', '')
    page = int(request.GET.get('page', 1))
    
    # Determine time period based on selected range
    now = timezone.now()
    if time_range == '1h':
        start_time = now - timedelta(hours=1)
        period_name = 'Last Hour'
    elif time_range == '12h':
        start_time = now - timedelta(hours=12)
        period_name = 'Last 12 Hours'
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
        period_name = 'Last 7 Days'
    elif time_range == '30d':
        start_time = now - timedelta(days=30)
        period_name = 'Last 30 Days'
    else:  # Default to 24h
        start_time = now - timedelta(days=1)
        period_name = 'Last 24 Hours'
        time_range = '24h'
    
    # Base queryset - filter for Apache logs only - handle both source types
    logs = ParsedLog.objects.filter(
        Q(raw_log__source__source_type='apache_access') | Q(raw_log__source__source_type='apache'),
        raw_log__timestamp__gte=start_time
    ).select_related('raw_log')
    
    # Apply status code filter
    if status_code != 'all':
        if status_code == '2xx':
            logs = logs.filter(status_code__gte=200, status_code__lt=300)
        elif status_code == '3xx':
            logs = logs.filter(status_code__gte=300, status_code__lt=400)
        elif status_code == '4xx':
            logs = logs.filter(status_code__gte=400, status_code__lt=500)
        elif status_code == '5xx':
            logs = logs.filter(status_code__gte=500)
        else:
            # Try to filter by specific status code
            try:
                logs = logs.filter(status_code=int(status_code))
            except ValueError:
                pass
    
    # Apply request method filter
    if request_method != 'all':
        logs = logs.filter(request_method=request_method)
    
    # Apply search filter if provided
    if search_query:
        logs = logs.filter(
            Q(request_path__icontains=search_query) | 
            Q(source_ip__icontains=search_query) |
            Q(user_agent__icontains=search_query)
        )
    
    # Get the TOTAL count using RawLog to match dashboard (THIS IS THE FIX)
    total_logs = RawLog.objects.filter(
        Q(source__source_type='apache_access') | Q(source__source_type='apache'),
        timestamp__gte=start_time
    ).count()
    
    # Get status code statistics (from ParsedLog)
    status_2xx = logs.filter(status_code__gte=200, status_code__lt=300).count()
    status_3xx = logs.filter(status_code__gte=300, status_code__lt=400).count()
    status_4xx = logs.filter(status_code__gte=400, status_code__lt=500).count()
    status_5xx = logs.filter(status_code__gte=500).count()
    
    # Get common request methods (adding this to API response)
    common_methods = list(logs.values('request_method').annotate(
        count=Count('request_method')
    ).order_by('-count')[:5])
    
    # Also get top paths and IPs for the refresh
    top_paths = list(logs.values('request_path').annotate(
        count=Count('request_path')
    ).order_by('-count')[:10])
    
    top_ips = list(logs.values('source_ip').annotate(
        count=Count('source_ip')
    ).order_by('-count')[:10])
    
    # Pagination
    per_page = 50
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    logs_paginated = logs.order_by('-raw_log__timestamp')[start_idx:end_idx]
    
    # Serialize logs for JSON response
    logs_data = []
    for log in logs_paginated:
        logs_data.append({
            'id': log.id,
            'request_method': log.request_method or 'UNKNOWN',
            'request_path': log.request_path or '/',
            'status_code': log.status_code or 0,
            'source_ip': log.source_ip or '0.0.0.0',
            'response_size': log.response_size,
            'raw_log': {
                'id': log.raw_log.id,
                'timestamp': log.raw_log.timestamp.isoformat()
            }
        })
    
    # Return JSON response with additional data
    return JsonResponse({
        'logs': logs_data,
        'stats': {
            'total_logs': total_logs,
            'status_2xx': status_2xx,
            'status_3xx': status_3xx,
            'status_4xx': status_4xx,
            'status_5xx': status_5xx,
            'period_name': period_name
        },
        'common_methods': common_methods,
        'top_paths': top_paths,
        'top_ips': top_ips
    })