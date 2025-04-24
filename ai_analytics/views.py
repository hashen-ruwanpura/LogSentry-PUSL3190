import logging
from datetime import datetime, timedelta
import json
import traceback

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.views.decorators.http import require_http_methods, require_POST, require_GET
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.core.paginator import Paginator
from django.db.models import Count, Sum
from django.conf import settings
from django.views.decorators.csrf import ensure_csrf_cookie
from django.urls import reverse

from .models import AIReport, AIReportFeedback
from .services import AIReportGeneratorAdapter, test_openrouter_api

logger = logging.getLogger(__name__)

@ensure_csrf_cookie
@login_required
def reports_dashboard(request):
    """Main dashboard view for AI reports"""
    try:
        # Get recent reports for this user
        recent_reports = AIReport.objects.filter(created_by=request.user).order_by('-generated_at')[:5]
        
        # Get report counts by type
        report_counts = AIReport.objects.filter(created_by=request.user).values('report_type').annotate(count=Count('id'))
        
        # Default time ranges
        today = timezone.now()
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)
        
        # Get report type choices for the dropdown
        report_types = AIReport.REPORT_TYPES
        
        context = {
            'recent_reports': recent_reports,
            'report_counts': report_counts,
            'default_start': week_ago.strftime('%Y-%m-%d'),
            'default_end': today.strftime('%Y-%m-%d'),
            'report_types': report_types,
            'active_nav': 'ai_reports',
            'page_title': 'AI Security Reports',
        }
        
        return render(request, 'authentication/ai_reports.html', context)
    except Exception as e:
        logger.error(f"Error in reports_dashboard: {str(e)}", exc_info=True)
        context = {
            'error': str(e),
            'active_nav': 'ai_reports',
            'page_title': 'AI Reports - Error',
        }
        return render(request, 'authentication/ai_reports.html', context)

@login_required
def report_detail(request, report_id):
    """View a single AI report in detail"""
    try:
        report = get_object_or_404(AIReport, id=report_id)
        
        # Check if the user has permission to view this report
        if report.created_by != request.user and not request.user.is_staff:
            return HttpResponseForbidden("You don't have permission to view this report")
        
        # Get related threats and incidents
        related_threats = report.related_threats.all()
        related_incidents = report.related_incidents.all()
        
        # Check if user has already provided feedback
        user_feedback = AIReportFeedback.objects.filter(report=report, user=request.user).first()
        
        context = {
            'report': report,
            'related_threats': related_threats,
            'related_incidents': related_incidents,
            'user_feedback': user_feedback,
            'active_nav': 'ai_reports',
            'page_title': report.title,
        }
        
        return render(request, 'authentication/report_detail.html', context)
    except Exception as e:
        logger.error(f"Error in report_detail: {str(e)}", exc_info=True)
        return redirect('ai_analytics:reports_dashboard')

@login_required
@require_GET
def report_json(request, report_id):
    """Get a single report as JSON for AJAX requests"""
    try:
        report = get_object_or_404(AIReport, id=report_id)
        
        # Check if the user has permission to view this report
        if report.created_by != request.user and not request.user.is_staff:
            return JsonResponse({"error": "Permission denied"}, status=403)
            
        return JsonResponse({
            'id': report.id,
            'title': report.title,
            'content': report.content,
            'report_type': report.report_type,
            'time_period_start': report.time_period_start.isoformat(),
            'time_period_end': report.time_period_end.isoformat(),
            'generated_at': report.generated_at.isoformat(),
            'source_filter': report.source_filter,
            'severity_filter': report.severity_filter,
        })
    except Exception as e:
        logger.error(f"Error in report_json: {str(e)}", exc_info=True)
        return JsonResponse({'error': str(e)}, status=500)

@ensure_csrf_cookie
@login_required
def generate_report_form(request):
    """View for the report generation form"""
    try:
        context = {
            'report_types': AIReport.REPORT_TYPES,
            'active_nav': 'ai_reports',
            'page_title': 'Generate AI Report'
        }
        return render(request, 'authentication/ai_reports.html', context)
    except Exception as e:
        logger.error(f"Error in generate_report_form view: {str(e)}", exc_info=True)
        return redirect('dashboard')

@login_required
@require_POST
def generate_ai_report(request):
    """API endpoint for generating a new AI report"""
    try:
        # Parse request parameters
        try:
            data = json.loads(request.body)
            logger.info(f"Received report generation request: {data}")
        except json.JSONDecodeError:
            logger.error("Invalid JSON in request body")
            return JsonResponse({'error': 'Invalid JSON in request body'}, status=400)
            
        report_type = data.get('report_type', 'security_summary')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        source_filter = data.get('source_filter', 'all')
        severity_filter = data.get('severity_filter', 'all')
        force_refresh = data.get('force_refresh', False)
        
        logger.info(f"Generating {report_type} report from {start_date} to {end_date} (filters: source={source_filter}, severity={severity_filter})")
        
        # Validate parameters
        if not start_date or not end_date:
            return JsonResponse({'error': 'Start date and end date are required'}, status=400)
            
        # Parse dates with robust error handling
        try:
            # Handle ISO format dates directly
            if 'T' in start_date:
                # ISO format with potential timezone info
                # Remove microseconds if present to avoid parsing issues
                start_date = start_date.split('.')[0].replace('Z', '+00:00')
                end_date = end_date.split('.')[0].replace('Z', '+00:00')
                
                # Parse with ISO format
                start_time = datetime.fromisoformat(start_date)
                end_time = datetime.fromisoformat(end_date)
            else:
                # Try multiple other formats
                formats_to_try = ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d']
                start_time = None
                end_time = None
                
                for fmt in formats_to_try:
                    try:
                        start_time = datetime.strptime(start_date, fmt)
                        end_time = datetime.strptime(end_date, fmt)
                        break
                    except ValueError:
                        continue
            
            if not start_time or not end_time:
                return JsonResponse({'error': 'Invalid date format. Try YYYY-MM-DD HH:MM:SS'}, status=400)
                
            # Make dates timezone aware
            if timezone.is_naive(start_time):
                start_time = timezone.make_aware(start_time)
            if timezone.is_naive(end_time):
                end_time = timezone.make_aware(end_time)
            
            logger.info(f"Parsed dates: {start_time} to {end_time}")
                
        except Exception as date_error:
            logger.error(f"Date parsing error: {str(date_error)}", exc_info=True)
            return JsonResponse({'error': f'Date parsing error: {str(date_error)}'}, status=400)
        
        # Generate report with comprehensive error handling
        try:
            # Initialize report generator
            generator = AIReportGeneratorAdapter()
            
            # Start log
            logger.info(f"Starting report generation for {report_type}")
            
            # Generate report
            report = generator.generate_report(
                report_type=report_type,
                start_time=start_time,
                end_time=end_time,
                source_filter=source_filter,
                severity_filter=severity_filter,
                user=request.user,
                force_refresh=force_refresh
            )
            
            if report:
                logger.info(f"Successfully generated report #{report.id}")
                
                # Return report details
                return JsonResponse({
                    'id': report.id,
                    'title': report.title, 
                    'content': report.content,
                    'report_type': report.report_type,
                    'generated_at': report.generated_at.isoformat(),
                })
            else:
                logger.error("Report generation failed - null report returned")
                return JsonResponse({
                    'error': 'Failed to generate report. See server logs for details.'
                }, status=500)
                
        except Exception as gen_error:
            # Log the full error with traceback
            logger.error(f"Error during report generation: {str(gen_error)}")
            logger.error(traceback.format_exc())
            
            # Return error details to the frontend
            return JsonResponse({
                'error': f'Report generation error: {str(gen_error)}'
            }, status=500)
            
    except Exception as e:
        logger.error(f"Unexpected error in generate_ai_report: {str(e)}", exc_info=True)
        return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)

@login_required
@require_POST
def submit_report_feedback(request, report_id):
    """Submit or update feedback for an AI report"""
    try:
        report = get_object_or_404(AIReport, pk=report_id)
        
        # Check permissions
        if not request.user.is_staff and report.created_by != request.user:
            return HttpResponseForbidden("You don't have permission to provide feedback for this report")
        
        # Parse request data
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
            
        rating = int(data.get('rating', 0))
        comments = data.get('comments', '')
        
        # Validate rating
        if not 1 <= rating <= 5:
            return JsonResponse({'error': 'Rating must be between 1 and 5'}, status=400)
        
        # Create or update feedback
        feedback, created = AIReportFeedback.objects.update_or_create(
            report=report,
            user=request.user,
            defaults={
                'rating': rating,
                'comments': comments,
                'submitted_at': timezone.now() # Update the timestamp on edit too
            }
        )
        
        return JsonResponse({
            'success': True,
            'feedback_id': feedback.id,
            'created': created,
            'updated': not created
        })
        
    except Exception as e:
        logger.error(f"Error in submit_report_feedback: {str(e)}", exc_info=True)
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["GET"])
def list_reports(request):
    """Get a list of reports for the current user with filtering options"""
    try:
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 10))
        report_type = request.GET.get('report_type')
        search_query = request.GET.get('q', '')
        
        # Base query - show all for admins, only user's reports for others
        if request.user.is_staff and request.GET.get('show_all') == 'true':
            reports = AIReport.objects.all().order_by('-generated_at')
        else:
            reports = AIReport.objects.filter(created_by=request.user).order_by('-generated_at')
        
        # Apply filters
        if report_type and report_type != 'all':
            reports = reports.filter(report_type=report_type)
            
        if search_query:
            reports = reports.filter(title__icontains=search_query)
        
        # Paginate
        paginator = Paginator(reports, page_size)
        page_obj = paginator.get_page(page)
        
        # Prepare response data
        reports_data = []
        for report in page_obj:
            reports_data.append({
                'id': report.id,
                'title': report.title,
                'report_type': report.report_type,
                'report_type_display': report.get_report_type_display(),
                'generated_at': report.generated_at.isoformat(),
                'time_period': f"{report.time_period_start.strftime('%Y-%m-%d')} to {report.time_period_end.strftime('%Y-%m-%d')}",
                'source_filter': report.source_filter,
                'severity_filter': report.severity_filter,
                'is_cached': report.is_cached,
                'created_by': report.created_by.username if report.created_by else "System"
            })
        
        # Calculate some usage statistics
        current_month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        stats = {
            'total_reports': AIReport.objects.filter(created_by=request.user).count(),
            'monthly_reports': AIReport.objects.filter(
                created_by=request.user,
                generated_at__gte=current_month_start
            ).count(),
            'total_tokens': AIReport.objects.filter(
                created_by=request.user
            ).aggregate(Sum('tokens_used')).get('tokens_used__sum', 0) or 0,
        }
        
        # Calculate token usage percentage if monthly limit is set
        monthly_token_limit = getattr(settings, 'MONTHLY_TOKEN_LIMIT', 100000)
        monthly_tokens_used = AIReport.objects.filter(
            created_by=request.user,
            generated_at__gte=current_month_start
        ).aggregate(Sum('tokens_used')).get('tokens_used__sum', 0) or 0
        
        stats['token_usage_percentage'] = min(100, int((monthly_tokens_used / monthly_token_limit) * 100))
        
        return JsonResponse({
            'reports': reports_data,
            'total': paginator.count,
            'pages': paginator.num_pages,
            'current_page': page,
            'has_next': page_obj.has_next(),
            'has_previous': page_obj.has_previous(),
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error in list_reports: {str(e)}", exc_info=True)
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_POST
def delete_report(request, report_id):
    """Delete an AI report"""
    try:
        report = get_object_or_404(AIReport, pk=report_id)
        
        # Check permissions
        if not request.user.is_staff and report.created_by != request.user:
            return JsonResponse({"error": "Permission denied"}, status=403)
            
        # Delete the report
        report.delete()
        
        return JsonResponse({"success": True})
        
    except Exception as e:
        logger.error(f"Error in delete_report: {str(e)}", exc_info=True)
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def test_api(request):
    """Test the OpenRouter API connectivity"""
    if not request.user.is_staff:
        return HttpResponseForbidden("Admin access required")
        
    try:
        success, response = test_openrouter_api()
        
        result = {
            'success': success,
            'response': response[:500] if success else response,
            'timestamp': timezone.now().isoformat(),
            'api_provider': 'OpenRouter'
        }
        
        return JsonResponse(result)
        
    except Exception as e:
        logger.error(f"Error in test_api: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }, status=500)