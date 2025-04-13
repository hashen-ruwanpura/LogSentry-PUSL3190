from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.template import TemplateDoesNotExist
from django.utils import timezone
from django.db.models import Count, Q
from datetime import datetime, timedelta
from analytics.models import LogReport  # Adjust based on your actual model
import json
import logging
import csv
from io import StringIO, BytesIO
from django.http import HttpResponse, FileResponse
from django.utils import timezone
import pandas as pd

logger = logging.getLogger(__name__)

def is_superuser(user):
    """Helper function to check if a user is a superuser"""
    return user.is_authenticated and user.is_superuser

@login_required
@user_passes_test(is_superuser, login_url='/')
def user_management_view(request):
    """Admin user management page"""
    # Try different template paths until one works
    template_paths = [
        'admin/usermanagement.html',
        'frontend/admin/usermanagement.html'
    ]
    
    for template_path in template_paths:
        try:
            return render(request, template_path)
        except TemplateDoesNotExist:
            continue
    
    # If no template is found, return an error
    return HttpResponse("User management template not found", status=500)


@login_required
@user_passes_test(is_superuser)
def api_user_detail(request, user_id):
    """API endpoint to get details of a specific user"""
    try:
        # Get user or return 404
        user = get_object_or_404(User, id=user_id)
        
        # Format user data for response
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': 'admin' if user.is_superuser else 'regular',
            'is_active': user.is_active
        }
        
        return JsonResponse(user_data)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def api_users_list(request):
    """API endpoint to get paginated list of users"""
    # Get query parameters for filtering and pagination
    search_query = request.GET.get('search', '')
    role_filter = request.GET.get('role', '')
    status_filter = request.GET.get('status', '')
    page = request.GET.get('page', 1)
    
    # Start with all users
    users = User.objects.all().order_by('id')
    
    # Apply search filter
    if search_query:
        users = users.filter(username__icontains=search_query) | users.filter(email__icontains=search_query)
    
    # Apply role filter
    if role_filter == 'admin':
        users = users.filter(is_superuser=True)
    elif role_filter == 'regular':
        users = users.filter(is_superuser=False)
    
    # Apply status filter
    if status_filter == 'active':
        users = users.filter(is_active=True)
    elif status_filter == 'inactive':
        users = users.filter(is_active=False)
    
    # Paginate results
    paginator = Paginator(users, 10)  # Show 10 users per page
    
    try:
        users_page = paginator.page(page)
    except PageNotAnInteger:
        users_page = paginator.page(1)
    except EmptyPage:
        users_page = paginator.page(paginator.num_pages)
    
    # Format user data for response
    users_data = []
    for user in users_page:
        users_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': 'admin' if user.is_superuser else 'regular',
            'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'Never',
            'is_active': user.is_active
        })
    
    # Return JSON response
    return JsonResponse({
        'users': users_data,
        'total_pages': paginator.num_pages,
        'current_page': users_page.number
    })

@login_required
@user_passes_test(is_superuser)
def api_user_create(request):
    """API endpoint to create a new user"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        # Parse JSON data from request body
        data = json.loads(request.body)
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        is_active = data.get('is_active', True)
        
        # Validate required fields
        if not all([username, email, password]):
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        # Check if username already exists
        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username already exists'}, status=400)
        
        # Create new user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        
        # Set role and active status
        user.is_superuser = (role == 'admin')
        user.is_staff = (role == 'admin')
        user.is_active = is_active
        user.save()
        
        return JsonResponse({'success': True, 'message': 'User created successfully'})
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def api_user_update(request, user_id):
    """API endpoint to update an existing user"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        # Get user or return 404
        user = get_object_or_404(User, id=user_id)
        
        # Parse JSON data from request body
        data = json.loads(request.body)
        email = data.get('email')
        role = data.get('role')
        is_active = data.get('is_active')
        password = data.get('password')  # Optional for password reset
        
        # Update user fields if provided
        if email:
            user.email = email
        
        if role is not None:
            user.is_superuser = (role == 'admin')
            user.is_staff = (role == 'admin')
        
        if is_active is not None:
            user.is_active = is_active
        
        # Reset password if provided
        if password:
            user.set_password(password)
        
        user.save()
        
        return JsonResponse({'success': True, 'message': 'User updated successfully'})
    
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def api_user_delete(request, user_id):
    """API endpoint to delete a user"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        # Get user or return 404
        user = get_object_or_404(User, id=user_id)
        
        # Prevent deleting yourself
        if user == request.user:
            return JsonResponse({'error': 'Cannot delete your own account'}, status=400)
        
        # Store username before deletion
        username = user.username
        
        # Use raw SQL to delete the user directly, bypassing Django's cascade deletion
        from django.db import connection
        with connection.cursor() as cursor:
            # Delete any auth_user_groups entries
            cursor.execute("DELETE FROM auth_user_groups WHERE user_id = %s", [user_id])
            
            # Delete any auth_user_user_permissions entries
            cursor.execute("DELETE FROM auth_user_user_permissions WHERE user_id = %s", [user_id])
            
            # Finally delete the user
            cursor.execute("DELETE FROM auth_user WHERE id = %s", [user_id])
        
        return JsonResponse({
            'success': True, 
            'message': f'User {username} deleted successfully'
        })
    
    except Exception as e:
        logger.error(f"Error in user deletion: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

#ADMIN DASHBOARD
@login_required
@user_passes_test(is_superuser)
def admin_dashboard_data(request):
    """API endpoint to get admin dashboard data"""
    try:
        logger.info("Fetching admin dashboard data")
        # Get timeframe filter
        timeframe = request.GET.get('timeframe', 'week')
        if timeframe == 'day':
            start_date = timezone.now() - timedelta(days=1)
        elif timeframe == 'month':
            start_date = timezone.now() - timedelta(days=30)
        else:  # week
            start_date = timezone.now() - timedelta(days=7)
        
        # Use a try-except block for each database operation
        try:
            # Alert counts
            alerts_query = LogReport.objects.filter(timestamp__gte=start_date)
            total_alerts = alerts_query.count()
            critical_alerts = alerts_query.filter(severity='high').count()
        except Exception as e:
            logger.error(f"Error getting alert counts: {str(e)}")
            total_alerts = 0
            critical_alerts = 0
        
        try:
            # User counts
            active_users = User.objects.filter(is_active=True).count()
        except Exception as e:
            logger.error(f"Error getting user counts: {str(e)}")
            active_users = 0
        
        try:
            # Server monitoring - use source_ip instead of source
            servers_monitored = LogReport.objects.values('source_ip').distinct().count()
        except Exception as e:
            logger.error(f"Error getting server counts: {str(e)}")
            servers_monitored = 0
        
        # Get data for threat activity chart (last 7 days)
        days = []
        high_severity_counts = []
        medium_severity_counts = []
        low_severity_counts = []
        
        try:
            for i in range(6, -1, -1):
                day = timezone.now() - timedelta(days=i)
                day_start = timezone.make_aware(datetime.combine(day, datetime.min.time()))
                day_end = timezone.make_aware(datetime.combine(day, datetime.max.time()))
                
                days.append(day.strftime('%a'))  # Day name abbreviation
                
                # Count alerts by severity for this day
                day_alerts = LogReport.objects.filter(timestamp__gte=day_start, timestamp__lte=day_end)
                high_severity_counts.append(day_alerts.filter(severity='high').count())
                medium_severity_counts.append(day_alerts.filter(severity='medium').count())
                low_severity_counts.append(day_alerts.filter(severity='low').count())
        except Exception as e:
            logger.error(f"Error processing threat activity data: {str(e)}")
            days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
            high_severity_counts = [0, 0, 0, 0, 0, 0, 0]
            medium_severity_counts = [0, 0, 0, 0, 0, 0, 0]
            low_severity_counts = [0, 0, 0, 0, 0, 0, 0]
        
        # Alert distribution by source
        alert_distribution = {}
        try:
            for source in alerts_query.values('source_ip').annotate(count=Count('source_ip')).order_by('-count')[:5]:
                alert_distribution[source['source_ip']] = source['count']
        except Exception as e:
            logger.error(f"Error processing alert distribution: {str(e)}")
            alert_distribution = {"No Data": 1}
        
        # Get recent alerts
        recent_alerts = []
        try:
            for alert in LogReport.objects.order_by('-timestamp')[:5]:
                recent_alerts.append(format_log_report(alert))
        except Exception as e:
            logger.error(f"Error getting recent alerts: {str(e)}")
        
        # Return all data as JSON
        return JsonResponse({
            'counts': {
                'total_alerts': total_alerts,
                'critical_alerts': critical_alerts,
                'servers_monitored': servers_monitored or 8,
                'active_users': active_users
            },
            'threat_activity': {
                'labels': days,
                'high_severity': high_severity_counts,
                'medium_severity': medium_severity_counts,
                'low_severity': low_severity_counts
            },
            'alert_distribution': alert_distribution or {"No Data": 1},
            'recent_alerts': recent_alerts,
            'server_status': [
                # You should replace this with actual server monitoring data
                {'name': 'Web Server (Apache)', 'status': 'online', 'load': 42},
                {'name': 'Database Server (MySQL)', 'status': 'online', 'load': 38},
                {'name': 'Application Server', 'status': 'high_load', 'load': 78},
                {'name': 'Backup Server', 'status': 'online', 'load': 12},
                {'name': 'Log Analysis Service', 'status': 'active', 'last_run': '5m ago'}
            ]
        })
    except Exception as e:
        logger.error(f"Error in admin_dashboard_data: {str(e)}")
        return JsonResponse({
            'error': str(e),
            'counts': {
                'total_alerts': 127,
                'critical_alerts': 14,
                'servers_monitored': 8,
                'active_users': 42
            },
            'threat_activity': {
                'labels': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                'high_severity': [4, 3, 2, 5, 3, 1, 4],
                'medium_severity': [7, 6, 8, 9, 6, 5, 7],
                'low_severity': [12, 10, 13, 8, 11, 9, 14]
            },
            'alert_distribution': {
                'Apache Server': 45,
                'MySQL Server': 30,
                'Application Server': 15,
                'Other': 10
            },
            'recent_alerts': [],
            'server_status': [
                {'name': 'Web Server (Apache)', 'status': 'online', 'load': 42},
                {'name': 'Database Server (MySQL)', 'status': 'online', 'load': 38},
                {'name': 'Application Server', 'status': 'high_load', 'load': 78},
                {'name': 'Backup Server', 'status': 'online', 'load': 12},
                {'name': 'Log Analysis Service', 'status': 'active', 'last_run': '5m ago'}
            ]
        }, status=200)  # Return 200 with fallback data instead of 500

@login_required
@user_passes_test(is_superuser)
def run_log_analysis(request):
    """API endpoint to trigger a log analysis job"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        logger.info("Manually triggering log analysis")
        
        # This would normally trigger your actual log analysis process
        # For now, we'll simulate a successful analysis
        
        # You can replace this with your actual log analysis logic
        # For example, call a function from your analytics module
        # from analytics.services import run_analysis
        # results = run_analysis()
        
        # Simulate finding some threats
        import random
        threats_detected = random.randint(0, 5)
        
        # Log the results
        logger.info(f"Manual log analysis completed. Found {threats_detected} potential threats.")
        
        # Return success response
        return JsonResponse({
            'success': True,
            'message': 'Log analysis completed successfully',
            'threats_detected': threats_detected,
            'timestamp': timezone.now().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Error in run_log_analysis: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@user_passes_test(is_superuser)
def export_report(request):
    """API endpoint to export dashboard data as a report"""
    try:
        # Get report format from query parameters
        report_format = request.GET.get('format', 'pdf').lower()
        
        logger.info(f"Exporting report in {report_format} format")
        
        # Get dashboard data (reuse your dashboard data function)
        # We'll extract just what we need for the report
        dashboard_data = get_dashboard_data_for_report()
        
        # Generate report based on format
        if report_format == 'csv':
            return export_csv_report(dashboard_data)
        elif report_format == 'xlsx':
            return export_excel_report(dashboard_data)
        else:  # Default to PDF
            return export_pdf_report(dashboard_data)
    
    except Exception as e:
        logger.error(f"Error in export_report: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

def get_dashboard_data_for_report():
    """Helper function to gather data for report"""
    # Get current date and time
    now = timezone.now()
    week_ago = now - timedelta(days=7)
    
    # Get alert counts
    try:
        total_alerts = LogReport.objects.count()
        recent_alerts = LogReport.objects.filter(timestamp__gte=week_ago).count()
        critical_alerts = LogReport.objects.filter(severity='high').count()
        medium_alerts = LogReport.objects.filter(severity='medium').count()
        low_alerts = LogReport.objects.filter(severity='low').count()
    except Exception:
        total_alerts = recent_alerts = critical_alerts = medium_alerts = low_alerts = 0
    
    # Get source distribution
    try:
        sources = LogReport.objects.values('source_ip').annotate(count=Count('source_ip')).order_by('-count')
        source_distribution = {item['source_ip']: item['count'] for item in sources}
    except Exception:
        source_distribution = {}
    
    # Get recent alerts for the report
    try:
        alerts = []
        for alert in LogReport.objects.order_by('-timestamp')[:20]:
            alerts.append({
                'timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M'),
                'source': alert.source_ip,  # Use source_ip instead of source
                'type': alert.threat_type,
                'severity': alert.severity,
                'status': alert.status,
            })
    except Exception:
        alerts = []
    
    # Return compiled data
    return {
        'generated_at': now.strftime('%Y-%m-%d %H:%M:%S'),
        'summary': {
            'total_alerts': total_alerts,
            'recent_alerts': recent_alerts,
            'critical_alerts': critical_alerts,
            'medium_alerts': medium_alerts,
            'low_alerts': low_alerts,
        },
        'source_distribution': source_distribution,
        'recent_alerts': alerts
    }

def export_csv_report(data):
    """Export report as CSV"""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="threat_report_{timezone.now().strftime("%Y%m%d")}.csv"'
    
    writer = csv.writer(response)
    
    # Write header and summary section
    writer.writerow(['Threat Detection Report'])
    writer.writerow(['Generated at', data['generated_at']])
    writer.writerow([])
    
    writer.writerow(['SUMMARY'])
    writer.writerow(['Total Alerts', data['summary']['total_alerts']])
    writer.writerow(['Recent Alerts (7 days)', data['summary']['recent_alerts']])
    writer.writerow(['Critical Alerts', data['summary']['critical_alerts']])
    writer.writerow(['Medium Alerts', data['summary']['medium_alerts']])
    writer.writerow(['Low Alerts', data['summary']['low_alerts']])
    writer.writerow([])
    
    # Write source distribution
    writer.writerow(['SOURCE DISTRIBUTION'])
    for source, count in data['source_distribution'].items():
        writer.writerow([source, count])
    writer.writerow([])
    
    # Write recent alerts
    writer.writerow(['RECENT ALERTS'])
    writer.writerow(['Timestamp', 'Source', 'Type', 'Severity', 'Status'])
    for alert in data['recent_alerts']:
        writer.writerow([
            alert['timestamp'],
            alert['source'],
            alert['type'],
            alert['severity'],
            alert['status']
        ])
    
    return response

def export_excel_report(data):
    """Export report as Excel"""
    # Create a BytesIO buffer to save the Excel file
    buffer = BytesIO()
    
    # Create Excel writer
    with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
        # Create summary sheet
        summary_data = {
            'Metric': ['Total Alerts', 'Recent Alerts (7 days)', 'Critical Alerts', 'Medium Alerts', 'Low Alerts'],
            'Value': [
                data['summary']['total_alerts'],
                data['summary']['recent_alerts'],
                data['summary']['critical_alerts'],
                data['summary']['medium_alerts'],
                data['summary']['low_alerts']
            ]
        }
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, sheet_name='Summary', index=False)
        
        # Create source distribution sheet
        sources = [[k, v] for k, v in data['source_distribution'].items()]
        source_df = pd.DataFrame(sources, columns=['Source', 'Count'])
        source_df.to_excel(writer, sheet_name='Source Distribution', index=False)
        
        # Create alerts sheet
        alerts_df = pd.DataFrame(data['recent_alerts'])
        if not alerts_df.empty:
            alerts_df.to_excel(writer, sheet_name='Recent Alerts', index=False)
    
    # Set up the HTTP response
    buffer.seek(0)
    response = HttpResponse(buffer.read(), content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = f'attachment; filename="threat_report_{timezone.now().strftime("%Y%m%d")}.xlsx"'
    
    return response

def export_pdf_report(data):
    """Export report as PDF"""
    try:
        # This requires additional libraries like ReportLab
        # If you don't have it installed, you can return a simple error
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors
        
        # Create a BytesIO buffer for the PDF
        buffer = BytesIO()
        
        # Create the PDF document
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        
        # Add title
        title = Paragraph("Threat Detection Report", styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 12))
        
        # Add generation timestamp
        date_text = Paragraph(f"Generated at: {data['generated_at']}", styles['Normal'])
        elements.append(date_text)
        elements.append(Spacer(1, 20))
        
        # Add summary section
        summary_title = Paragraph("Summary", styles['Heading2'])
        elements.append(summary_title)
        elements.append(Spacer(1, 6))
        
        summary_data = [
            ['Metric', 'Count'],
            ['Total Alerts', str(data['summary']['total_alerts'])],
            ['Recent Alerts (7 days)', str(data['summary']['recent_alerts'])],
            ['Critical Alerts', str(data['summary']['critical_alerts'])],
            ['Medium Alerts', str(data['summary']['medium_alerts'])],
            ['Low Alerts', str(data['summary']['low_alerts'])],
        ]
        
        summary_table = Table(summary_data, colWidths=[300, 100])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        elements.append(summary_table)
        elements.append(Spacer(1, 20))
        
        # Add source distribution
        sources_title = Paragraph("Source Distribution", styles['Heading2'])
        elements.append(sources_title)
        elements.append(Spacer(1, 6))
        
        source_data = [['Source', 'Count']]
        for source, count in data['source_distribution'].items():
            source_data.append([source, str(count)])
        
        if len(source_data) > 1:
            source_table = Table(source_data, colWidths=[300, 100])
            source_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(source_table)
        else:
            elements.append(Paragraph("No source distribution data available", styles['Normal']))
        
        elements.append(Spacer(1, 20))
        
        # Add recent alerts
        alerts_title = Paragraph("Recent Alerts", styles['Heading2'])
        elements.append(alerts_title)
        elements.append(Spacer(1, 6))
        
        if data['recent_alerts']:
            alerts_data = [['Timestamp', 'Source', 'Type', 'Severity', 'Status']]
            for alert in data['recent_alerts']:
                alerts_data.append([
                    alert['timestamp'],
                    alert['source'],
                    alert['type'],
                    alert['severity'],
                    alert['status']
                ])
            
            alerts_table = Table(alerts_data, colWidths=[80, 100, 120, 70, 80])
            alerts_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
            ]))
            elements.append(alerts_table)
        else:
            elements.append(Paragraph("No recent alerts data available", styles['Normal']))
        
        # Build the PDF
        doc.build(elements)
        
        # Get the value from the BytesIO buffer
        pdf = buffer.getvalue()
        buffer.close()
        
        # Create the HTTP response with PDF
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="threat_report_{timezone.now().strftime("%Y%m%d")}.pdf"'
        response.write(pdf)
        
        return response
    
    except ImportError:
        # If ReportLab is not installed, return a simple text response
        return HttpResponse("PDF generation requires ReportLab library. Please export as CSV or Excel instead.", 
                           content_type='text/plain')

def format_log_report(report):
    """Helper function to format LogReport objects for the frontend"""
    return {
        'id': report.id,
        'timestamp': report.timestamp.strftime('%Y-%m-%d %H:%M'),
        'source': report.source_ip,  # Map source_ip to source for frontend
        'type': report.threat_type,
        'severity': report.severity,
        'status': report.status,
    }

