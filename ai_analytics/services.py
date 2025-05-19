import logging
import json
from datetime import datetime, timedelta
import traceback
import time
from typing import Dict, List, Any, Optional, Union

from django.utils import timezone
from django.conf import settings
from django.db.models import Q

# Import your models
from .models import AIReport, AIReportFeedback
from log_ingestion.models import ParsedLog, RawLog
from threat_detection.models import Threat, Incident, BlacklistedIP
from siem.models import ApacheLogEntry, MySQLLogEntry  # Correctly capitalized

# Set up logging
logger = logging.getLogger(__name__)

class OpenRouterReportGenerator:
    """Service to generate AI reports using OpenRouter API"""
    
    def __init__(self):
        try:
            # Import here to avoid issues if the package isn't installed
            from openai import OpenAI
            
            # Get API key from settings
            self.api_key = getattr(settings, 'OPENROUTER_API_KEY', None)
            if not self.api_key:
                logger.error("OpenRouter API key not found in settings")
                raise ValueError("OpenRouter API key is not configured")
                
            # Initialize OpenRouter client
            self.client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=self.api_key
            )
            
            # Get model from settings or use default
            self.model = getattr(settings, 'OPENROUTER_MODEL', 'openai/gpt-4o-mini')
            
            # Set up additional parameters
            self.site_url = getattr(settings, 'SITE_URL', 'https://log-detection-platform.example.com')
            self.site_name = getattr(settings, 'SITE_NAME', 'Log Detection Platform')
            
            logger.info(f"OpenRouter API initialized with model: {self.model}")
        except ImportError:
            logger.error("OpenAI package not installed. Run: pip install openai")
            raise ImportError("OpenAI package not installed. Run: pip install openai")
        except Exception as e:
            logger.error(f"Failed to initialize OpenRouter API: {str(e)}")
            raise ValueError(f"OpenRouter API initialization error: {str(e)}")
    
    def generate_report(self, report_type: str, context_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a report based on provided data using OpenRouter"""
        start_time = time.time()
        try:
            # Create a prompt based on report type and data
            prompt = self._create_prompt(report_type, context_data)
            
            # Log the attempt (without the full prompt for security)
            logger.info(f"Sending OpenRouter API request for {report_type} report (prompt length: {len(prompt)})")
            
            # Call OpenRouter API with retry handling
            for attempt in range(3):
                try:
                    # Make the API call
                    response = self.client.chat.completions.create(
                        extra_headers={
                            "HTTP-Referer": self.site_url,
                            "X-Title": self.site_name,
                        },
                        model=self.model,
                        messages=[
                            {"role": "system", "content": "You are a cybersecurity analyst specializing in log analysis and threat detection."},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0.2,
                        max_tokens=2000,
                    )
                    
                    # Process response
                    if response.choices and response.choices[0].message.content:
                        content = response.choices[0].message.content
                        execution_time = time.time() - start_time
                        
                        logger.info(f"Successfully generated {report_type} report with OpenRouter (length: {len(content)}, time: {execution_time:.2f}s)")
                        
                        # Estimate token usage
                        tokens_used = len(prompt) // 4 + len(content) // 4  # Rough estimate
                        
                        return {
                            'content': content,
                            'tokens_used': tokens_used,
                            'execution_time': execution_time,
                            'success': True
                        }
                    else:
                        logger.warning("OpenRouter returned empty response")
                        raise ValueError("Empty response from OpenRouter API")
                        
                except Exception as api_error:
                    logger.warning(f"OpenRouter API attempt {attempt+1} failed: {str(api_error)}")
                    if attempt < 2:  # Wait before retrying, except on last attempt
                        time.sleep(2 ** attempt)  # Exponential backoff (1s, 2s)
                    else:
                        raise  # Re-raise on last attempt
            
        except Exception as e:
            error_msg = f"Error with OpenRouter API: {str(e)}"
            logger.error(error_msg, exc_info=True)
            
            return {
                'content': f"## Error Generating Report\n\nWe encountered a technical issue while generating your report.\n\nError details: {str(e)}\n\nPlease try again later.",
                'tokens_used': 0,
                'execution_time': time.time() - start_time,
                'success': False,
                'error': str(e)
            }
    
    def _create_prompt(self, report_type: str, context_data: Dict[str, Any]) -> str:
        """Create an effective prompt for AI report generation"""
        
        # Basic intro that clearly defines the task
        intro = "As a cybersecurity analyst, create a comprehensive security report based on the following log data and events."
        
        # Format time period information
        time_info = f"Time period: {context_data.get('start_time', 'N/A')} to {context_data.get('end_time', 'N/A')}"
        
        # Format filter information
        filter_info = f"Source filter: {context_data.get('source_filter', 'all')}\nSeverity filter: {context_data.get('severity_filter', 'all')}"
        
        # Format statistics summary
        stats_summary = f"""
Key metrics:
- Total logs analyzed: {context_data.get('total_logs', 0)}
- High severity alerts: {context_data.get('high_alerts', 0)}
- Authentication failures: {context_data.get('auth_failures', 0)}
- Total threats detected: {context_data.get('total_threats', 0)}
- Unresolved threats: {context_data.get('unresolved_threats', 0)}
"""

        # Add sample threats if available
        threats_info = ""
        if context_data.get('threats'):
            threats = context_data.get('threats', [])[:5]  # Limit to 5 threats
            threats_info = "Sample threats:\n"
            for i, threat in enumerate(threats):
                threats_info += f"- Threat {i+1}: {threat.get('description', 'Unknown')} (Severity: {threat.get('severity', 'Unknown')})\n"
        
        # Add sample logs if available
        logs_sample = ""
        if context_data.get('apache_logs'):
            apache_logs = context_data.get('apache_logs', [])[:3]  # Limit to 3 logs
            logs_sample += "\nApache log samples:\n"
            for i, log in enumerate(apache_logs):
                logs_sample += f"- Log {i+1}: IP: {log.get('client_ip', 'unknown')}, Status: {log.get('status_code', '?')}, Path: {log.get('request_path', '/')[:50]}\n"
        
        if context_data.get('mysql_logs'):
            mysql_logs = context_data.get('mysql_logs', [])[:3]  # Limit to 3 logs
            logs_sample += "\nMySQL log samples:\n"
            for i, log in enumerate(mysql_logs):
                logs_sample += f"- Log {i+1}: Type: {log.get('log_type', 'unknown')}, Message: {log.get('message', '')[:50]}\n"
        
        # Report-specific instructions
        report_instructions = {
            "security_summary": "Create a general security summary highlighting key findings, risks, and recommendations.",
            "incident_analysis": "Analyze specific security incidents, their impact, and possible mitigations.",
            "root_cause": "Perform root cause analysis on security events to identify underlying issues.",
            "anomaly_detection": "Identify unusual patterns that might indicate security threats.",
            "prediction": "Based on current trends, predict potential future security concerns.",
            "user_behavior": "Analyze user activity patterns and identify suspicious behaviors.",
            "cross_source": "Compare and correlate data across different log sources."
        }
        
        # Get instructions for this report type
        specific_instructions = report_instructions.get(
            report_type, 
            "Create a general security report based on the provided data."
        )
        
        # Format output instructions
        output_format = """
Format your response in Markdown with the following sections:

## Executive Summary
(Brief overview of key findings)

## Security Analysis
(Detailed analysis based on the provided data)

## Recommendations
(Actionable steps to address identified issues)

Keep your analysis professional, factual, and security-focused.
"""
        
        # Combine all parts into a complete prompt
        prompt = f"""
{intro}

{time_info}
{filter_info}

{stats_summary}
{threats_info}
{logs_sample}

TASK: {specific_instructions}

{output_format}
"""
        
        # ONLY modify the prediction report type case, leaving everything else intact
        if report_type == 'prediction':
            # Check if system metrics are available in the context data
            system_metrics = context_data.get('system_metrics', {})
            if system_metrics:
                # Add system metrics section only for prediction reports and only if data exists
                prompt += f"""

## System Resource Metrics Analysis

Please include a detailed analysis of the following system metrics in your report, correlating them with security events where possible:
"""

                # Add CPU metrics if available
                if 'cpu' in system_metrics:
                    cpu = system_metrics['cpu']
                    prompt += f"""
### CPU Usage:
- Current: {cpu.get('usage', 'N/A')}%
- Trend: {cpu.get('trend', 'Unknown')} ({cpu.get('trend_value', 0):.2f}% per day)
- Prediction: {cpu.get('message', 'No prediction available')}
- Confidence: {cpu.get('confidence', 'N/A')}%
"""

                # Add Memory metrics if available
                if 'memory' in system_metrics:
                    memory = system_metrics['memory']
                    prompt += f"""
### Memory Usage:
- Current: {memory.get('usage', 'N/A')}% ({memory.get('used', 'N/A')} GB of {memory.get('total', 'N/A')} GB)
- Trend: {memory.get('trend', 'Unknown')} ({memory.get('trend_value', 0):.2f}% per day)
- Prediction: {memory.get('message', 'No prediction available')}
- Confidence: {memory.get('confidence', 'N/A')}%
"""

                # Add Disk metrics if available
                if 'disk' in system_metrics:
                    disk = system_metrics['disk']
                    prompt += f"""
### Disk Usage:
- Current: {disk.get('usage', 'N/A')}% ({disk.get('used', 'N/A')} GB of {disk.get('total', 'N/A')} GB)
- Trend: {disk.get('trend', 'Unknown')} ({disk.get('trend_value', 0):.2f}% per day)
- Prediction: {disk.get('message', 'No prediction available')}
- Confidence: {disk.get('confidence', 'N/A')}%
"""

                # Add Log Volume metrics if available
                if 'log_volume' in system_metrics:
                    log_vol = system_metrics['log_volume']
                    prompt += f"""
### Log Volume:
- Current: {log_vol.get('usage', 'N/A')}% ({log_vol.get('used', 'N/A')} GB of allocated space)
- Apache Logs: {log_vol.get('apache_size', 'N/A')} GB (growing {log_vol.get('apache_growth', 0):.2f} GB/week)
- MySQL Logs: {log_vol.get('mysql_size', 'N/A')} GB (growing {log_vol.get('mysql_growth', 0):.2f} GB/week)
- System Logs: {log_vol.get('system_size', 'N/A')} GB (growing {log_vol.get('system_growth', 0):.2f} GB/week)
- Prediction: {log_vol.get('message', 'No prediction available')}
- Confidence: {log_vol.get('confidence', 'N/A')}%
"""

                # Add correlation analysis instructions
                prompt += """

Please analyze correlations between system metrics and security events. For example:
1. Do CPU/memory spikes correspond with increased security incidents?
2. Is log volume growth correlated with specific types of attacks?
3. Are there resource patterns that precede certain categories of security events?

Your analysis should include:
1. Integrated security and performance risk assessment
2. Predictions for both security threats and resource constraints
3. Prioritized recommendations that address both security vulnerabilities and system performance issues
4. Timeline predictions for when critical thresholds might be reached if current trends continue
"""

        # Return the prompt (unmodified or with our additions for prediction reports)
        return prompt


class AIReportGenerator:
    """Legacy OpenAI implementation - kept for compatibility"""
    
    def __init__(self):
        """Initialize with basic settings"""
        self.api_key = getattr(settings, 'OPENAI_API_KEY', None)
        self.model = getattr(settings, 'OPENAI_MODEL', 'gpt-3.5-turbo')
        self.max_tokens = getattr(settings, 'OPENAI_MAX_TOKENS', 1000)
        self.temperature = getattr(settings, 'OPENAI_TEMPERATURE', 0.2)
        
        # Check for API key
        if not self.api_key or self.api_key == 'your-api-key-here':
            logger.warning("OpenAI API key is not properly configured")
    
    def generate_report(self, report_type, start_time, end_time, 
                      source_filter=None, severity_filter=None,
                      user=None, force_refresh=False):
        """Generate a security report based on the specified parameters"""
        try:
            # Step 1: Check if we have a cached report
            if not force_refresh:
                cached_report = self._check_cache(report_type, start_time, end_time,
                                               source_filter, severity_filter)
                if cached_report:
                    logger.info(f"Using cached report {cached_report.id}")
                    return cached_report
            
            # Step 2: Extract data for the time period
            data = self._extract_data_for_time_period(start_time, end_time, 
                                               source_filter, severity_filter)
            
            # Step 3: Format prompt for OpenAI
            prompt = self._create_prompt(report_type, data)
            
            # Step 4: Call OpenAI API (using OpenRouter adapter instead)
            openrouter = OpenRouterReportGenerator()
            
            # Format context data for OpenRouter
            context_data = {
                'start_time': data['time_range']['start'],
                'end_time': data['time_range']['end'],
                'source_filter': source_filter or 'all',
                'severity_filter': severity_filter or 'all',
                'total_logs': data['stats'].get('total_logs', 0),  # Use the direct count from RawLog
                'high_alerts': data['stats'].get('high_severity', 0),
                'auth_failures': data['stats'].get('auth_failures', 0),
                'total_threats': data['stats'].get('total_threats', 0),
                'unresolved_threats': data['stats'].get('unresolved_threats', 0),
                'threats': data.get('threats', []),
                'apache_logs': data.get('apache_logs', []),
                'mysql_logs': data.get('mysql_logs', [])
            }
            
            # In the method where you prepare data for AI reports
            if report_type == 'prediction':
                # Import the function from views_predictive
                from authentication.views_predictive import get_system_metrics
                
                # Get system metrics and add to context data
                try:
                    system_metrics = get_system_metrics()
                    context_data['system_metrics'] = system_metrics
                except Exception as e:
                    logger.error(f"Error getting system metrics: {e}")
                    # Proceed without system metrics if they can't be obtained
            
            result = openrouter.generate_report(report_type, context_data)
            
            if not result.get('success'):
                logger.error("Failed to generate report with OpenRouter API")
                return None
            
            # Step 5: Save and return the report
            title = f"{report_type.replace('_', ' ').title()} - {start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')}"
            
            report = self._save_report(
                report_type=report_type,
                title=title,
                content=result['content'],
                start_time=start_time,
                end_time=end_time,
                source_filter=source_filter,
                severity_filter=severity_filter,
                tokens_used=result['tokens_used'],
                user=user
            )
            
            return report
            
        except Exception as e:
            logger.exception(f"Error in report generation: {str(e)}")
            return None
    
    def _check_cache(self, report_type, start_time, end_time, source_filter, severity_filter):
        """Check if we have a recent report that matches these parameters"""
        try:
            # Calculate the cache validity threshold
            cache_hours = getattr(settings, 'AI_REPORT_CACHE_HOURS', 24)
            cache_threshold = timezone.now() - timedelta(hours=cache_hours)
            
            # Query for matching reports
            query = Q(report_type=report_type) & \
                   Q(time_period_start=start_time) & \
                   Q(time_period_end=end_time) & \
                   Q(generated_at__gt=cache_threshold)
                   
            if source_filter:
                query &= Q(source_filter=source_filter)
                
            if severity_filter:
                query &= Q(severity_filter=severity_filter)
                
            # Get the most recent matching report
            report = AIReport.objects.filter(query).order_by('-generated_at').first()
            
            return report
        except Exception as e:
            logger.error(f"Error checking report cache: {str(e)}")
            return None
    
    def _extract_data_for_time_period(self, start_time, end_time, source_filter=None, severity_filter=None):
        """Extract relevant data for the specified time period and filters"""
        try:
            data = {
                'time_range': {
                    'start': start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'end': end_time.strftime('%Y-%m-%d %H:%M:%S')
                },
                'stats': {},
                'apache_logs': [],
                'mysql_logs': [],
                'threats': [],
                'incidents': []
            }
            
            # IMPORTANT FIX: Get total logs from RawLog table directly, consistent with dashboard
            from log_ingestion.models import RawLog
            data['stats']['total_logs'] = RawLog.objects.filter(
                timestamp__gte=start_time, 
                timestamp__lte=end_time
            ).count()
            
            # Apply source filter
            apache_filter = Q(timestamp__gte=start_time) & Q(timestamp__lte=end_time)
            mysql_filter = Q(timestamp__gte=start_time) & Q(timestamp__lte=end_time)
            threat_filter = Q(created_at__gte=start_time) & Q(created_at__lte=end_time)
            incident_filter = Q(created_at__gte=start_time) & Q(created_at__lte=end_time)
            
            # Apply severity filter if specified
            if severity_filter and severity_filter != 'all':
                apache_filter &= Q(status_code__gte=400) if severity_filter == 'high' else Q(status_code__lt=400)
                threat_filter &= Q(severity=severity_filter)
                incident_filter &= Q(severity=severity_filter)
            
            # Get Apache logs
            if source_filter in ('all', 'apache'):
                apache_logs = ApacheLogEntry.objects.filter(apache_filter).order_by('-timestamp')[:100]
                data['apache_logs'] = [
                    {
                        'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                        'client_ip': log.client_ip,
                        'request_method': log.request_method,
                        'request_path': log.request_url,
                        'status_code': log.status_code,
                        'bytes_sent': log.bytes_sent,
                        'user_agent': log.user_agent
                    }
                    for log in apache_logs
                ]
                data['stats']['total_apache_logs'] = ApacheLogEntry.objects.filter(apache_filter).count()
                data['stats']['error_logs'] = ApacheLogEntry.objects.filter(apache_filter & Q(status_code__gte=400)).count()
                
            # Get MySQL logs
            if source_filter in ('all', 'mysql'):
                mysql_logs = MySQLLogEntry.objects.filter(mysql_filter).order_by('-timestamp')[:100]
                data['mysql_logs'] = [
                    {
                        'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                        'severity': log.severity,
                        'message': log.message,
                        'user': log.user,
                        'host': log.host,
                        'subsystem': log.subsystem
                    }
                    for log in mysql_logs
                ]
                data['stats']['total_mysql_logs'] = MySQLLogEntry.objects.filter(mysql_filter).count()
            
            # Get threats
            threats = Threat.objects.filter(threat_filter).order_by('-created_at')[:50]
            data['threats'] = [
                {
                    'timestamp': threat.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'severity': threat.severity,
                    'status': threat.status,
                    'description': threat.description,
                    'source_ip': threat.source_ip,
                    'user_id': threat.user_id,
                    'affected_system': threat.affected_system
                }
                for threat in threats
            ]
            data['stats']['total_threats'] = Threat.objects.filter(threat_filter).count()
            data['stats']['high_severity'] = Threat.objects.filter(threat_filter & Q(severity='high')).count()
            data['stats']['unresolved_threats'] = Threat.objects.filter(threat_filter & ~Q(status='resolved')).count()
            
            # Get incidents
            incidents = Incident.objects.filter(incident_filter).order_by('-start_time')[:20]
            data['incidents'] = [
                {
                    'name': incident.name,
                    'description': incident.description,
                    'severity': incident.severity,
                    'status': incident.status,
                    'start_time': incident.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'end_time': incident.end_time.strftime('%Y-%m-%d %H:%M:%S') if incident.end_time else None,
                    'affected_ips': incident.affected_ips,
                    'affected_users': incident.affected_users
                }
                for incident in incidents
            ]
            data['stats']['total_incidents'] = Incident.objects.filter(incident_filter).count()
            
            # Count authentication failures
            data['stats']['auth_failures'] = ApacheLogEntry.objects.filter(
                apache_filter & 
                (Q(status_code=401) | Q(status_code=403))
            ).count() if source_filter in ('all', 'apache') else 0
            
            # Get blacklisted IPs
            blacklisted = BlacklistedIP.objects.filter(active=True).count()
            data['stats']['blacklisted_ips'] = blacklisted
            
            return data
            
        except Exception as e:
            logger.exception(f"Error extracting data for report: {str(e)}")
            # Return minimal data structure
            return {
                'time_range': {
                    'start': start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'end': end_time.strftime('%Y-%m-%d %H:%M:%S')
                },
                'stats': {
                    'error': str(e)
                },
                'apache_logs': [],
                'mysql_logs': [],
                'threats': [],
                'incidents': []
            }
    
    def _create_prompt(self, report_type, data):
        """Create a prompt for OpenAI based on the extracted data"""
        # This is just a placeholder - actual implementation uses OpenRouter
        return "This is a placeholder prompt. Using OpenRouter implementation instead."
    
    def _save_report(self, report_type, title, content, start_time, end_time, 
                   source_filter, severity_filter, tokens_used, user=None):
        """Save the generated report to the database"""
        try:
            report = AIReport(
                report_type=report_type,
                title=title,
                content=content,
                time_period_start=start_time,
                time_period_end=end_time,
                source_filter=source_filter,
                severity_filter=severity_filter,
                tokens_used=tokens_used,
                generated_at=timezone.now(),
                created_by=user
            )
            report.save()
            
            # Associate related threats and incidents if needed
            # For simplicity, not implemented here
            
            return report
        except Exception as e:
            logger.exception(f"Error saving report: {str(e)}")
            return None


class AIReportGeneratorAdapter:
    """Adapter class that handles the transition between different AI providers"""
    
    def __init__(self):
        """Initialize with the appropriate provider based on settings"""
        # We're using OpenRouter directly now
        self.use_openrouter = True
        self.generator = AIReportGenerator()
        self.api_name = "OpenRouter"
        logger.info("Using OpenRouter for AI report generation")
    
    def generate_report(self, report_type, start_time, end_time, 
                      source_filter=None, severity_filter=None, 
                      user=None, force_refresh=False):
        """Generate a report using the configured AI provider"""
        try:
            # We use the AIReportGenerator which now uses OpenRouter internally
            return self.generator.generate_report(
                report_type=report_type,
                start_time=start_time,
                end_time=end_time,
                source_filter=source_filter,
                severity_filter=severity_filter,
                user=user,
                force_refresh=force_refresh
            )
        except Exception as e:
            logger.exception(f"Error in adapter.generate_report: {str(e)}")
            return None


class FallbackReportGenerator:
    """Emergency fallback generator when API services fail"""
    
    def generate_report(self, report_type, context_data):
        """Generate a simple report without using external APIs"""
        
        start_time = context_data.get('start_time', 'Unknown')
        end_time = context_data.get('end_time', 'Unknown')
        total_logs = context_data.get('total_logs', 0)
        high_alerts = context_data.get('high_alerts', 0)
        
        report_title = report_type.replace('_', ' ').title()
        
        # Generate a simple markdown report
        content = f"""
## {report_title}

**Time Period:** {start_time} to {end_time}

### Executive Summary

This is a fallback report generated due to API connectivity issues. The system analyzed {total_logs} logs during this period and found {high_alerts} high severity alerts.

### Security Analysis

Based on the available data:
- {total_logs} total log entries were processed
- {high_alerts} high severity alerts were detected
- Further analysis requires restored API functionality

### Recommendations

1. Review the high severity alerts manually
2. Check system connectivity to AI services
3. Try generating a complete report when API services are restored
        """
        
        return {
            'content': content,
            'tokens_used': 0,
            'success': True
        }


class AlertAnalysisService:
    """Service for analyzing individual security alerts with AI"""
    
    def __init__(self):
        """Initialize the service using the existing OpenRouter configuration"""
        try:
            from ai_analytics.services import OpenRouterReportGenerator
            self.openrouter = OpenRouterReportGenerator()
            logger.info("AlertAnalysisService initialized with OpenRouterReportGenerator")
        except Exception as e:
            logger.error(f"Error initializing AlertAnalysisService: {str(e)}")
            raise
    
    def analyze_threat(self, threat, action_type='analyze'):
        """Analyze a threat/alert with AI and return insights"""
        try:
            # Log the attempt
            logger.info(f"Analyzing threat ID #{threat.id} with action: {action_type}")
            
            # Prepare context data about the threat
            context = self._prepare_threat_context(threat)
            
            # Generate prompt based on action type
            prompt = self._create_prompt(threat, action_type, context)
            
            # Call OpenRouter API
            response = self.openrouter.client.chat.completions.create(
                extra_headers={
                    "HTTP-Referer": self.openrouter.site_url,
                    "X-Title": self.openrouter.site_name,
                },
                model=self.openrouter.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity analyst specializing in threat detection and analysis."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=1000,
            )
            
            # Process response
            if response.choices and response.choices[0].message.content:
                analysis = response.choices[0].message.content
                logger.info(f"Successfully analyzed threat #{threat.id}, generated {len(analysis)} characters")
                return analysis
            else:
                logger.warning(f"Empty response from OpenRouter API for threat #{threat.id}")
                return "AI couldn't generate a response. Please try again."
                
        except Exception as e:
            error_msg = f"Error analyzing threat with AI: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error analyzing threat: {str(e)}"
    
    def _prepare_threat_context(self, threat):
        """Prepare context data about the threat for AI analysis"""
        try:
            # Get related parsed log if available
            related_log = None
            raw_log_content = None
            if hasattr(threat, 'parsed_log') and threat.parsed_log:
                related_log = threat.parsed_log
                if hasattr(related_log, 'raw_log'):
                    raw_log_content = related_log.raw_log.content
            
            # Get similar threats
            similar_threats = Threat.objects.filter(
                Q(source_ip=threat.source_ip) | Q(mitre_tactic=threat.mitre_tactic)
            ).exclude(id=threat.id).order_by('-created_at')[:3]
            
            # Format similar threats
            similar_threats_data = []
            for st in similar_threats:
                similar_threats_data.append({
                    'id': st.id,
                    'created_at': st.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'severity': st.severity,
                    'status': st.status,
                    'description': st.description,
                    'mitre_tactic': st.mitre_tactic,
                    'source_ip': st.source_ip,
                })
            
            # Check if IP is blacklisted
            is_blacklisted = False
            if threat.source_ip:
                is_blacklisted = BlacklistedIP.objects.filter(ip_address=threat.source_ip).exists()
            
            # Build context dictionary
            context = {
                'threat': {
                    'id': threat.id,
                    'created_at': threat.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'updated_at': threat.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'severity': threat.severity,
                    'status': threat.status,
                    'source_ip': threat.source_ip or 'Unknown',
                    'affected_system': threat.affected_system or 'Not specified',
                    'mitre_tactic': threat.mitre_tactic or 'Unclassified',
                    'mitre_technique': threat.mitre_technique or 'Unclassified',
                    'description': threat.description,
                    'recommendation': getattr(threat, 'recommendation', 'No recommendation provided'),
                    'is_ip_blacklisted': is_blacklisted,
                },
                'related_log': {
                    'available': related_log is not None,
                    'content': raw_log_content,
                    'timestamp': related_log.timestamp.strftime('%Y-%m-%d %H:%M:%S') if related_log and hasattr(related_log, 'timestamp') else None,
                    'request_method': getattr(related_log, 'request_method', None),
                    'request_path': getattr(related_log, 'request_path', None),
                    'status_code': getattr(related_log, 'status_code', None),
                    'user_agent': getattr(related_log, 'user_agent', None),
                },
                'similar_threats': similar_threats_data,
            }
            
            return context
            
        except Exception as e:
            logger.error(f"Error preparing threat context: {str(e)}")
            # Return minimal context to avoid analysis failure
            return {
                'threat': {
                    'id': threat.id,
                    'severity': getattr(threat, 'severity', 'unknown'),
                    'description': getattr(threat, 'description', 'No description available'),
                },
                'related_log': {'available': False},
                'similar_threats': []
            }
    
    def _create_prompt(self, threat, action_type, context):
        """Create a prompt for the AI based on the action type"""
        base_prompt = (
            f"Security alert #{threat.id} - {threat.severity.upper()} severity\n"
            f"Description: {threat.description}\n\n"
        )
        
        if context['related_log']['available'] and context['related_log']['content']:
            base_prompt += f"Related log entry:\n{context['related_log']['content'][:500]}\n\n"
            
        if threat.mitre_tactic:
            base_prompt += f"MITRE ATT&CK Tactic: {threat.mitre_tactic}\n"
            
        if threat.mitre_technique:
            base_prompt += f"MITRE ATT&CK Technique: {threat.mitre_technique}\n\n"
            
        # Add similar threats if available
        if context['similar_threats']:
            base_prompt += "Similar threats detected:\n"
            for st in context['similar_threats']:
                base_prompt += f"- #{st['id']}: {st['severity']} severity, {st['description'][:100]}...\n"
            base_prompt += "\n"
            
        # Action-specific prompts
        if action_type == 'explain':
            base_prompt += (
                "Please explain this security alert in detail, including:\n"
                "1. What this alert means in simple terms\n"
                "2. The potential impact if this is a real threat\n"
                "3. Common causes for this type of alert\n"
                "4. Whether this alert appears to be a false positive based on the information provided\n"
                "\nFormat your response in clear sections with markdown headings."
            )
        elif action_type == 'suggest':
            base_prompt += (
                "Please suggest specific solutions for addressing this security alert, including:\n"
                "1. Immediate mitigation steps\n"
                "2. Long-term fixes to prevent similar issues\n"
                "3. Security hardening recommendations\n"
                "4. Monitoring suggestions to detect similar threats\n"
                "\nProvide actionable, specific steps rather than generic advice. Format your response with markdown."
            )
        elif action_type == 'risk':
            base_prompt += (
                "Please provide a risk assessment of this security alert, including:\n"
                "1. The potential business impact if exploited\n"
                "2. The likelihood of exploitation based on the information provided\n"
                "3. A risk score (Critical, High, Medium, Low) with justification\n"
                "4. Factors that might increase or decrease the risk level\n"
                "\nFormat your response in clear sections with markdown."
            )
        elif action_type == 'related':
            base_prompt += (
                "Based on the alert details, please identify:\n"
                "1. Related attack patterns that might accompany this alert\n"
                "2. Other MITRE ATT&CK techniques often used alongside this one\n"
                "3. Indicators of compromise (IoCs) to look for in other systems\n"
                "4. Associated threat actors or groups known to use these techniques\n"
                "\nFormat your response in clear sections with markdown."
            )
        else:  # Default analyze action
            base_prompt += (
                "Please analyze this security alert comprehensively and provide insights, including:\n"
                "1. Analysis of what happened and why this alert was triggered\n"
                "2. Assessment of severity and whether it matches the assigned level\n"
                "3. Recommended next steps for investigation\n"
                "4. Potential remediation actions\n"
                "\nFormat your response in clear sections with markdown."
            )
            
        return base_prompt
    
def test_openrouter_api():
    """Debug function to test OpenRouter API directly"""
    try:
        print("Testing OpenRouter API connection...")
        
        # Import here to avoid issues if not installed
        from openai import OpenAI
        
        # Get API key from settings
        api_key = getattr(settings, 'OPENROUTER_API_KEY', None)
        if not api_key:
            print("OpenRouter API key not found in settings")
            return False, "API key not configured"
            
        # Initialize client
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key
        )
        
        # Get model
        model = getattr(settings, 'OPENROUTER_MODEL', 'openai/gpt-4o-mini')
        
        print(f"Using model: {model}")
        
        # Make test request
        response = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": "https://log-detection-platform.example.com",
                "X-Title": "Log Detection Platform",
            },
            model=model,
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst."},
                {"role": "user", "content": "Create a brief security summary for a web server."}
            ],
            temperature=0.2,
            max_tokens=300,
        )
        
        # Check response
        if response.choices and response.choices[0].message:
            content = response.choices[0].message.content
            print(f"API response received, length: {len(content or '')}")
            print("First 100 characters:", (content or "")[:100])
            return True, content
        else:
            print("API returned empty response")
            return False, "Empty response"
            
    except Exception as e:
        print(f"API test failed: {str(e)}")
        return False, str(e)