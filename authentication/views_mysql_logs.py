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
def mysql_logs_view(request):
    """
    View for displaying and analyzing MySQL database logs.
    Provides filtering, search and statistics specific to MySQL logs.
    """
    # Get filter parameters
    time_range = request.GET.get('time_range', '24h')
    query_type = request.GET.get('query_type', 'all')
    execution_time = request.GET.get('execution_time', 'all')
    search_query = request.GET.get('search', '')
    page = int(request.GET.get('page', 1))
    export_format = request.GET.get('export')  # Add export format parameter
    
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
    
    # Base queryset - filter for MySQL logs only - Handle both MySQL types
    logs = ParsedLog.objects.filter(
        Q(raw_log__source__source_type='mysql') | Q(raw_log__source__source_type='mysql_error'),
        raw_log__timestamp__gte=start_time
    ).select_related('raw_log')
    
    # Apply query type filter
    if query_type != 'all':
        # Use regex to find query type regardless of leading whitespace/comments
        logs = logs.filter(query__iregex=r'^\s*' + query_type)
    
    # Apply execution time filter
    if execution_time == 'fast':
        logs = logs.filter(execution_time__lt=1.0)
    elif execution_time == 'medium':
        logs = logs.filter(execution_time__gte=1.0, execution_time__lt=5.0)
    elif execution_time == 'slow':
        logs = logs.filter(execution_time__gte=5.0)
    
    # Apply search filter if provided
    if search_query:
        logs = logs.filter(
            Q(query__icontains=search_query) | 
            Q(user_id__icontains=search_query)
        )
    
    # Get statistics
    total_logs = RawLog.objects.filter(
        Q(source__source_type='mysql') | Q(source__source_type='mysql_error'),
        timestamp__gte=start_time
    ).count()
    slow_queries = logs.filter(execution_time__gte=1.0).count()
    
    # Get query type distribution
    query_types = []
    for qt in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER', 'DROP']:
        # Use regex to match query types regardless of whitespace
        count = logs.filter(query__iregex=r'^\s*' + qt).count()
        if count > 0:
            query_types.append({
                'type': qt,
                'count': count,
                'percentage': round(count / total_logs * 100, 1) if total_logs > 0 else 0
            })
    
    # Get top users
    top_users = logs.values('user_id').annotate(
        count=Count('user_id')
    ).order_by('-count')[:10]
    
    # Get slowest queries
    slowest_queries = logs.order_by('-execution_time')[:5]
    
    # Handle PDF export
    if export_format == 'pdf':
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.graphics.shapes import Drawing, Rect
        from io import BytesIO
        from django.http import HttpResponse
        
        # Define LogSentry brand colors
        brand_primary = colors.HexColor('#3f51b5')  # Primary blue
        brand_secondary = colors.HexColor('#6c757d')
        brand_light = colors.HexColor('#f5f7fa')
        brand_dark = colors.HexColor('#212529')
        
        # Create response object
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="LogSentry_MySQL_Logs_{timezone.now().strftime("%Y%m%d_%H%M")}.pdf"'
        
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
            canvas.drawString(140, doc.height + doc.topMargin + 6, "MySQL Database Logs")
            
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
        
        # Add a decorative line function
        def add_separator():
            elements.append(Spacer(1, 6))
            line = Drawing(500, 2)
            line.add(Rect(0, 0, 500, 1, fillColor=brand_primary, strokeColor=None))
            elements.append(line)
            elements.append(Spacer(1, 15))
        
        # First page / Cover
        elements.append(Spacer(1, 30))
        
        # Title
        elements.append(Paragraph("MySQL Database Logs", styles['LogSentryTitle']))
        elements.append(Spacer(1, 10))
        
        # Period and filters subtitle
        report_subtitle = f"{period_name}"
        if query_type != 'all':
            report_subtitle += f" - Query Type: {query_type}"
        if execution_time != 'all':
            report_subtitle += f" - Execution Time: {execution_time}"
        if search_query:
            report_subtitle += f" - Search: {search_query}"
        
        elements.append(Paragraph(report_subtitle, styles['Heading2']))
        elements.append(Spacer(1, 30))
        
        # Executive Summary Section
        elements.append(Paragraph("Executive Summary", styles['LogSentryHeading1']))
        add_separator()
        
        elements.append(Paragraph(
            "This report provides an analysis of MySQL database logs. "
            "It summarizes query patterns, performance metrics, and user activity across database servers "
            "monitored by LogSentry during the selected time period.",
            styles['LogSentryNormal']
        ))
        elements.append(Spacer(1, 20))
        
        # Key Metrics Section
        elements.append(Paragraph("Key Metrics", styles['LogSentryHeading2']))
        
        # Summary statistics in a better-looking table
        stats_data = [
            ['Metric', 'Value', 'Details'],
            ['Total Queries', str(total_logs), period_name],
            ['Optimal Queries', str(total_logs - slow_queries), 
             f"{((total_logs - slow_queries) / max(total_logs, 1) * 100):.1f}% of total"],
            ['Slow Queries', str(slow_queries), 
             f"{(slow_queries / max(total_logs, 1) * 100):.1f}% of total"],
        ]
        
        # Create and style the summary table
        summary_table = Table(stats_data, colWidths=[180, 120, 220])
        summary_table.setStyle(TableStyle([
            # Header styling
            ('BACKGROUND', (0, 0), (-1, 0), brand_primary),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            
            # Data rows styling
            ('BACKGROUND', (0, 1), (0, -1), colors.HexColor('#f5f7fa')),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (1, 1), (1, -1), 'CENTER'),
            
            # Grid styling
            ('GRID', (0, 0), (-1, -1), 0.5, brand_secondary),
            ('BOX', (0, 0), (-1, -1), 1, brand_primary),
            
            # Alternating row colors
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f8f9fa')),
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#f8f9fa')),
        ]))
        
        elements.append(summary_table)
        elements.append(Spacer(1, 20))
        
        # Query Type Distribution
        elements.append(Paragraph("Query Type Distribution", styles['LogSentryHeading2']))
        elements.append(Spacer(1, 10))
        
        if query_types:
            # Create table data for query types
            query_data = [['Query Type', 'Count', 'Percentage']]
            
            for qt in query_types:
                query_data.append([
                    qt['type'],
                    str(qt['count']),
                    f"{qt['percentage']}%"
                ])
            
            # Create and style query types table
            query_table = Table(query_data, colWidths=[150, 150, 150])
            query_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), brand_primary),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ALIGN', (1, 1), (1, -1), 'CENTER'),
                ('ALIGN', (2, 1), (2, -1), 'CENTER'),
                
                # Alternating row colors
                *[('BACKGROUND', (0, i), (-1, i), colors.HexColor('#f8f9fa')) 
                  for i in range(1, len(query_data)) if i % 2 == 0]
            ]))
            
            elements.append(query_table)
        else:
            elements.append(Paragraph("No query type data available", styles['LogSentryNormal']))
        
        elements.append(Spacer(1, 20))
        elements.append(PageBreak())
        
        # Top Users Section
        elements.append(Paragraph("Most Active Database Users", styles['LogSentryHeading1']))
        add_separator()
        
        if top_users:
            user_data = [['User', 'Query Count', 'Percentage']]
            
            for user in top_users:
                user_id = user['user_id'] or 'system'
                percentage = (user['count'] / max(total_logs, 1) * 100)
                
                user_data.append([
                    user_id,
                    str(user['count']),
                    f"{percentage:.1f}%"
                ])
            
            # Create and style users table
            users_table = Table(user_data, colWidths=[200, 150, 150])
            users_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), brand_primary),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ALIGN', (1, 1), (1, -1), 'CENTER'),
                ('ALIGN', (2, 1), (2, -1), 'CENTER'),
                
                # Alternating row colors
                *[('BACKGROUND', (0, i), (-1, i), colors.HexColor('#f8f9fa')) 
                  for i in range(1, len(user_data)) if i % 2 == 0]
            ]))
            
            elements.append(users_table)
        else:
            elements.append(Paragraph("No user activity data available", styles['LogSentryNormal']))
        
        elements.append(Spacer(1, 20))
        
        # Slowest Queries Section
        elements.append(Paragraph("Slowest Queries", styles['LogSentryHeading2']))
        elements.append(Spacer(1, 10))
        
        if slowest_queries:
            slow_data = [['User', 'Execution Time', 'Query']]
            
            for query in slowest_queries:
                # Safely handle query text which might be None
                query_text = query.query or '-'
                if len(query_text) > 80:
                    query_text = query_text[:80] + '...'
                
                # Safely handle execution_time which might be None
                execution_time = "-" if query.execution_time is None else f"{query.execution_time:.2f}s"
                
                slow_data.append([
                    query.user_id or 'system',
                    execution_time,  # Now safely handled
                    query_text
                ])
            
            # Create and style slow queries table
            slow_table = Table(slow_data, colWidths=[100, 100, 300])
            slow_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), brand_primary),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ALIGN', (1, 1), (1, -1), 'CENTER'),
                
                # Alternating row colors
                *[('BACKGROUND', (0, i), (-1, i), colors.HexColor('#f8f9fa')) 
                  for i in range(1, len(slow_data)) if i % 2 == 0]
            ]))
            
            elements.append(slow_table)
        else:
            elements.append(Paragraph("No slow query data available", styles['LogSentryNormal']))
        
        elements.append(Spacer(1, 30))
        elements.append(PageBreak())
        
        # MySQL Queries Detail Section
        elements.append(Paragraph("MySQL Query Details", styles['LogSentryHeading1']))
        add_separator()
        
        # Create log records table (limit to 100 for reasonable PDF size)
        logs_data = [['Timestamp', 'User', 'Query', 'Execution Time', 'Rows', 'Status']]
        
        # Use the filtered logs but limit to 100 records for PDF
        log_records = logs.order_by('-raw_log__timestamp')[:100]
        
        for log in log_records:
            # Safely handle query which might be None
            query = log.query or '-'
            if len(query) > 50:
                query = query[:50] + '...'
            
            # Safely handle execution_time which might be None
            execution_time = "-" if log.execution_time is None else f"{log.execution_time:.2f}s"
            
            logs_data.append([
                log.raw_log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.user_id or 'system',
                query,
                execution_time,  # Now safely handled
                str(getattr(log, 'rows_affected', 0)),
                log.status or 'unknown'
            ])
        
        if len(logs_data) > 1:
            # Create table with style
            logs_table = Table(logs_data, colWidths=[100, 80, 220, 70, 40, 60])
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
        
        # Add recommendations section
        elements.append(Spacer(1, 30))
        elements.append(Paragraph("Database Performance Recommendations", styles['LogSentryHeading2']))
        elements.append(Spacer(1, 5))
        
        # Add recommendations based on the data
        recommendations = []
        
        if slow_queries > 0:
            percentage = (slow_queries / max(total_logs, 1) * 100)
            if percentage > 15:
                recommendations.append(
                    "• <b>High Percentage of Slow Queries:</b> Consider optimizing database indexes and query structures."
                )
            elif percentage > 5:
                recommendations.append(
                    "• <b>Moderate Number of Slow Queries:</b> Review query execution plans for queries taking over 1 second."
                )
            
            # Add specific recommendations based on query types
            for qt in query_types:
                if qt['type'] == 'SELECT' and qt['percentage'] > 50:
                    recommendations.append(
                        "• <b>High SELECT Query Volume:</b> Review caching strategies and implement read replicas if appropriate."
                    )
                elif qt['type'] == 'INSERT' and qt['percentage'] > 30:
                    recommendations.append(
                        "• <b>High INSERT Query Volume:</b> Consider batch processing and optimized bulk inserts."
                    )
                elif qt['type'] == 'UPDATE' and qt['percentage'] > 20:
                    recommendations.append(
                        "• <b>High UPDATE Query Volume:</b> Review update patterns and ensure proper indexing."
                    )
        
        # Add general recommendations
        recommendations.append(
            "• Regularly review and maintain database indexes"
        )
        recommendations.append(
            "• Implement query caching where appropriate"
        )
        recommendations.append(
            "• Set up alerts for queries exceeding 5 seconds execution time"
        )
        
        for rec in recommendations:
            elements.append(Paragraph(rec, styles['LogSentryNormal']))
        
        # Build PDF document with custom page template
        doc.build(elements, onFirstPage=add_page_elements, onLaterPages=add_page_elements)
        
        # Get PDF content
        pdf = buffer.getvalue()
        buffer.close()
        response.write(pdf)
        
        return response
    
    # Pagination for normal HTML view
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
    
    context = {
        'logs': logs_paginated,
        'total_logs': total_logs,
        'period_name': period_name,
        'time_range': time_range,
        'query_type': query_type,
        'execution_time': execution_time,
        'search_query': search_query,
        'slow_queries': slow_queries,
        'normal_queries': total_logs - slow_queries,
        'query_types': query_types,
        'top_users': top_users,
        'slowest_queries': slowest_queries,
        'current_page': page,
        'total_pages': total_pages,
        'page_range': page_range,
        'has_next': page < total_pages,
        'has_prev': page > 1,
        'next_page': page + 1,
        'prev_page': page - 1,
    }
    
    return render(request, 'authentication/mysql_logs.html', context)

@login_required
def mysql_logs_api(request):
    """API endpoint for fetching MySQL logs data via AJAX"""
    try:
        # Get filter parameters (same as mysql_logs_view)
        time_range = request.GET.get('time_range', '24h')
        query_type = request.GET.get('query_type', 'all')
        execution_time = request.GET.get('execution_time', 'all')
        search_query = request.GET.get('search', '')
        
        try:
            page = int(request.GET.get('page', 1))
        except ValueError:
            page = 1
        
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
        
        # Base queryset - filter for MySQL logs only - Handle both MySQL types
        logs = ParsedLog.objects.filter(
            Q(raw_log__source__source_type='mysql') | Q(raw_log__source__source_type='mysql_error'),
            raw_log__timestamp__gte=start_time
        ).select_related('raw_log')
        
        # Apply query type filter
        if query_type != 'all':
            # Use regex to find query type regardless of leading whitespace/comments
            logs = logs.filter(query__iregex=r'^\s*' + query_type)
        
        # Apply execution time filter
        if execution_time == 'fast':
            logs = logs.filter(execution_time__lt=1.0)
        elif execution_time == 'medium':
            logs = logs.filter(execution_time__gte=1.0, execution_time__lt=5.0)
        elif execution_time == 'slow':
            logs = logs.filter(execution_time__gte=5.0)
        
        # Apply search filter if provided
        if search_query:
            logs = logs.filter(
                Q(query__icontains=search_query) | 
                Q(user_id__icontains=search_query)
            )
        
        # Get statistics
        total_logs = RawLog.objects.filter(
            Q(source__source_type='mysql') | Q(source__source_type='mysql_error'),
            timestamp__gte=start_time
        ).count()
        slow_queries = logs.filter(execution_time__gte=1.0).count()
        
        # Get query type distribution
        query_types = []
        for qt in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER', 'DROP']:
            # Use regex to match query types regardless of whitespace
            count = logs.filter(query__iregex=r'^\s*' + qt).count()
            if count > 0:
                query_types.append({
                    'type': qt,
                    'count': count,
                    'percentage': round(count / total_logs * 100, 1) if total_logs > 0 else 0
                })
        
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
                'user_id': log.user_id or 'system',
                'query': log.query,
                'execution_time': log.execution_time,
                'rows_affected': getattr(log, 'rows_affected', 0),
                'status': log.status,
                'raw_log': {
                    'id': log.raw_log.id,
                    'timestamp': log.raw_log.timestamp.isoformat()
                }
            })
        
        # Return JSON response
        return JsonResponse({
            'logs': logs_data,
            'stats': {
                'total_logs': total_logs,
                'slow_queries': slow_queries,
                'normal_queries': total_logs - slow_queries,
                'query_types': query_types,
                'period_name': period_name
            }
        })
    
    except Exception as e:
        # Log the error
        logging.error(f"Error in mysql_logs_api: {str(e)}")
        
        # Return a basic error response
        return JsonResponse({
            'error': 'An error occurred while fetching log data',
            'logs': [],
            'stats': {
                'total_logs': 0,
                'slow_queries': 0,
                'normal_queries': 0,
                'query_types': [],
                'period_name': 'Error'
            }
        }, status=500)

def handle_mysql_logs_error(request, error_message):
    """Helper function to log errors and return a friendly error response"""
    logging.error(f"MySQL logs error: {error_message}")
    
    if 'application/json' in request.headers.get('Accept', ''):
        return JsonResponse({
            'error': 'An error occurred while processing MySQL logs',
            'message': str(error_message),
            'logs': [],
            'stats': {
                'total_logs': 0,
                'slow_queries': 0,
                'normal_queries': 0,
                'query_types': []
            }
        }, status=500)
    else:
        return render(request, 'authentication/mysql_logs.html', {
            'error_message': str(error_message),
            'logs': [],
            'total_logs': 0
        })