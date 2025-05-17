import time
import threading
import logging
import os
import re
import json
from datetime import datetime
from django.utils import timezone
from django.conf import settings
from django.db import transaction
from .models import LogSource, RawLog, ParsedLog, LogFilePosition
from .collectors import EnhancedLogCollectionManager
from threat_detection.rules import RuleEngine

logger = logging.getLogger(__name__)

def json_safe_encoder(obj):
    """Helper function to make objects JSON serializable"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

class RealtimeLogProcessor:
    """
    A singleton class that manages continuous real-time log processing
    """
    _instance = None
    _lock = threading.Lock()
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
        
    def __init__(self):
        self.collection_manager = None
        self.rule_engine = RuleEngine()
        self.running = False
        self.enabled = True  # Default state
        self.thread = None
        self.file_watch_thread = None
        self.last_processed_time = timezone.now()
        self.file_positions = {}  # Track file positions in memory
        self.log_sources = []  # Track active log sources
        self.processing_interval = 30  # Default: 30 seconds
        self.logs_per_batch = 50  # Default: 50 logs per batch
        # Set to track already alerted threat signatures (for deduplication)
        self.alerted_threats = set() 
        self._load_user_settings()  # Load user settings on initialization
    
    def _load_user_settings(self):
        """Load real-time analysis settings from the database"""
        try:
            # Try to get settings from the SystemSettings model
            from authentication.models import SystemSettings
            
            # Get interval setting
            interval_setting = SystemSettings.objects.filter(
                section='real_time_analysis',
                settings_key='interval'
            ).first()
            
            if interval_setting and interval_setting.settings_value:
                try:
                    self.processing_interval = max(10, min(300, int(interval_setting.settings_value)))
                    logger.info(f"Loaded interval setting from DB: {self.processing_interval} seconds")
                except (ValueError, TypeError):
                    logger.warning(f"Invalid interval setting: {interval_setting.settings_value}")
            
            # Get logs count setting
            logs_count_setting = SystemSettings.objects.filter(
                section='real_time_analysis',
                settings_key='logs_count'
            ).first()
            
            if logs_count_setting and logs_count_setting.settings_value:
                try:
                    self.logs_per_batch = max(10, min(500, int(logs_count_setting.settings_value)))
                    logger.info(f"Loaded logs_count setting from DB: {self.logs_per_batch} logs")
                except (ValueError, TypeError):
                    logger.warning(f"Invalid logs_count setting: {logs_count_setting.settings_value}")
                    
            # Get enabled setting
            enabled_setting = SystemSettings.objects.filter(
                section='real_time_analysis',
                settings_key='enabled'
            ).first()
            
            if enabled_setting and enabled_setting.settings_value:
                self.enabled = enabled_setting.settings_value.lower() == 'true'
                logger.info(f"Loaded enabled setting from DB: {self.enabled}")
            else:
                self.enabled = True
                
        except Exception as e:
            logger.warning(f"Error loading user settings: {str(e)}")
        
    def start(self, interval=None, logs_count=None, enabled=None):
        """Start the real-time log processor with configurable parameters"""
        # Stop if already running
        if self.running:
            self.stop()
            time.sleep(1)  # Give time to clean up
            
        # Use provided parameters or defaults from settings
        if interval is not None:
            self.processing_interval = max(10, min(300, int(interval)))
        if logs_count is not None:
            self.logs_per_batch = max(10, min(500, int(logs_count)))
        if enabled is not None:
            self.enabled = bool(enabled)
            
        # Save settings to database for persistence
        self._save_settings(self.processing_interval, self.logs_per_batch, self.enabled)
        
        # If disabled, don't start processing
        if not self.enabled:
            logger.info("Real-time log processor is disabled by user settings")
            return True
            
        # Initialize log collection manager
        try:
            # Get log sources with validation
            log_sources = LogSource.objects.filter(enabled=True)
            
            # Check if we have any valid sources
            if not log_sources.exists():
                logger.warning("No enabled log sources found - creating defaults")
                # Create default sources before continuing
                self._create_default_sources()
                log_sources = LogSource.objects.filter(enabled=True)
            
            clean_log_files = []
            valid_sources = []
            
            for source in log_sources:
                # Check for invalid paths
                if not source.file_path or source.file_path.strip() == "":
                    logger.warning(f"Skipping log source with empty path: {source.name}")
                    continue
                    
                # Clean and normalize the path
                clean_path = source.file_path.strip().strip('"\'')
                clean_path = os.path.normpath(clean_path)
                
                # Skip paths that are just '.' or have no directory component
                if clean_path == "." or os.path.dirname(clean_path) == "":
                    logger.warning(f"Invalid log path for {source.name}: {clean_path}")
                    continue
                
                # Verify file exists (but don't fail if it doesn't - might be created later)
                if not os.path.exists(clean_path):
                    logger.warning(f"Log file doesn't exist at path: {clean_path}. Will monitor for creation.")
                
                # Update the source in database if needed
                if clean_path != source.file_path:
                    source.file_path = clean_path
                    source.save(update_fields=['file_path'])
                
                clean_log_files.append({
                    'path': clean_path,
                    'type': source.source_type
                })
                valid_sources.append(source)
            
            # Don't proceed if we have no valid log files
            if not clean_log_files:
                logger.error("No valid log files to monitor")
                return False
                
            # Store sources for direct file monitoring
            self.log_sources = valid_sources
            
            # Create config dictionary based on available log sources
            config = {
                'use_filebeat': getattr(settings, 'USE_FILEBEAT', False),
                'filebeat_config': getattr(settings, 'FILEBEAT_CONFIG_PATH', 'config/filebeat.yml'),
                'log_files': clean_log_files
            }
            
            self.collection_manager = EnhancedLogCollectionManager(config)
            
            # Initialize file positions from database
            self._initialize_file_positions()
            
            # Start the processing thread
            self.running = True
            self.thread = threading.Thread(target=self._continuous_processing)
            self.thread.daemon = True
            self.thread.start()
            
            # Start active file monitoring thread
            self.file_watch_thread = threading.Thread(target=self._active_file_monitoring)
            self.file_watch_thread.daemon = True
            self.file_watch_thread.start()
            
            # Reset alerted threats set when starting
            self.alerted_threats = set()
            
            logger.info(f"Real-time log processor started with interval={self.processing_interval}s, batch={self.logs_per_batch}")
            return True
        except Exception as e:
            logger.error(f"Failed to start real-time log processor: {str(e)}", exc_info=True)
            return False
        
    def _save_settings(self, interval, logs_count, enabled):
        """Save real-time analysis settings to database for persistence"""
        try:
            from authentication.models import SystemSettings
            
            # Save interval setting
            SystemSettings.objects.update_or_create(
                section='real_time_analysis',
                settings_key='interval',
                defaults={
                    'settings_value': str(interval),
                    'last_updated': timezone.now()
                }
            )
            
            # Save logs count setting
            SystemSettings.objects.update_or_create(
                section='real_time_analysis',
                settings_key='logs_count',
                defaults={
                    'settings_value': str(logs_count),
                    'last_updated': timezone.now()
                }
            )
            
            # Save enabled setting
            SystemSettings.objects.update_or_create(
                section='real_time_analysis',
                settings_key='enabled',
                defaults={
                    'settings_value': 'true' if enabled else 'false',
                    'last_updated': timezone.now()
                }
            )
            
            logger.info(f"Saved real-time analysis settings: interval={interval}, logs_count={logs_count}, enabled={enabled}")
        except Exception as e:
            logger.error(f"Error saving real-time analysis settings: {str(e)}")
            
    def _initialize_file_positions(self):
        """Initialize file positions for all active log sources"""
        self.file_positions = {}
        
        for source in self.log_sources:
            try:
                # Skip invalid paths
                if not source.file_path or not os.path.exists(source.file_path):
                    continue
                
                # Get file size
                file_size = os.path.getsize(source.file_path)
                
                # Get position from database or use file size if there's no record
                position, created = LogFilePosition.objects.get_or_create(
                    source=source,
                    defaults={
                        'position': file_size,  # Start from the END for new files
                        'last_read': timezone.now()
                    }
                )
                
                # CRITICAL FIX: Always ensure we start from the end, never the beginning
                # This prevents re-processing old entries that might be ignored due to whitelisting
                if created or position.position == 0:
                    position.position = file_size  
                    position.save()
                    logger.info(f"New file position set to END for {source.file_path}: {file_size} bytes")
            
                # Store in memory
                self.file_positions[source.id] = {
                    'path': source.file_path,
                    'position': position.position,
                    'last_read': position.last_read,
                    'size': file_size,
                    'source': source
                }
                
            except Exception as e:
                logger.error(f"Error initializing position for {source.name}: {str(e)}")
                
    def _make_json_serializable(self, data):
        """Fix datetime objects in dictionaries to make them JSON serializable"""
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if isinstance(value, datetime):
                    # Ensure datetime is timezone-aware
                    if timezone.is_naive(value):
                        value = timezone.make_aware(value, timezone.get_default_timezone())
                    # Convert datetime to ISO format string
                    result[key] = value.isoformat()
                elif isinstance(value, dict):
                    # Recursively process nested dictionaries
                    result[key] = self._make_json_serializable(value)
                elif isinstance(value, list):
                    # Process lists
                    result[key] = [
                        self._make_json_serializable(item) if isinstance(item, (dict, datetime)) else item
                        for item in value
                    ]
                else:
                    result[key] = value
            return result
        elif isinstance(data, datetime):
            # Ensure datetime is timezone-aware
            if timezone.is_naive(data):
                data = timezone.make_aware(data, timezone.get_default_timezone())
            return data.isoformat()
        else:
            return data
                
    def _active_file_monitoring(self):
        """Actively monitor log files for changes and create RawLog entries"""
        logger.info("Starting active file monitoring thread")
        
        while self.running and self.enabled:
            try:
                for source_id, info in list(self.file_positions.items()):
                    source = info['source']
                    file_path = info['path']
                    last_pos = info['position']
                    
                    if not os.path.exists(file_path):
                        # Skip if file doesn't exist yet
                        continue
                        
                    # Get current file size
                    try:
                        current_size = os.path.getsize(file_path)
                    except OSError:
                        logger.warning(f"Cannot access {file_path}. Skipping.")
                        continue
                    
                    # File size changed?
                    if current_size > last_pos:
                        # New content available
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
                                # Seek to the last position
                                file.seek(last_pos)
                                
                                # Read new content
                                new_content = file.read()
                                
                                if new_content.strip():
                                    # Process new content line by line
                                    lines = new_content.splitlines()
                                    logger.info(f"Read {len(lines)} new lines from {file_path}")
                                    
                                    # Create raw logs in transaction to ensure atomic operation
                                    with transaction.atomic():
                                        for line in lines:
                                            if line.strip():
                                                # Create RawLog entry with timezone-aware timestamp
                                                RawLog.objects.create(
                                                    source=source,
                                                    content=line.strip(),
                                                    timestamp=timezone.now(),
                                                    is_parsed=False
                                                )
                                    
                                    # Update file position
                                    info['position'] = current_size
                                    info['last_read'] = timezone.now()
                                    
                                    # Update database position
                                    LogFilePosition.objects.update_or_create(
                                        source=source,
                                        defaults={
                                            'position': current_size,
                                            'last_read': timezone.now()
                                        }
                                    )
                        except Exception as e:
                            logger.error(f"Error reading from {file_path}: {str(e)}")
                    
                    # If file shrank, it was probably rotated
                    elif current_size < last_pos:
                        logger.info(f"File {file_path} appears to have been rotated. Resetting position.")
                        info['position'] = 0
                        LogFilePosition.objects.update_or_create(
                            source=source,
                            defaults={
                                'position': 0,
                                'last_read': timezone.now()
                            }
                        )
                
                # Short sleep between checks to reduce CPU usage
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in file monitoring: {str(e)}")
                time.sleep(5)  # Longer sleep on error
    
    def _continuous_processing(self):
        """Continuous log processing loop that properly analyzes logs from all pages"""
        logger.info("Starting enhanced continuous log processing loop")
        
        next_run_time = timezone.now()
        
        while self.running and self.enabled:
            try:
                current_time = timezone.now()
                
                # Check if it's time to run the analysis and we're enabled
                if current_time >= next_run_time and self.enabled:
                    # Find unprocessed logs - USING USER-DEFINED BATCH SIZE
                    from django.db.models import Q
                    
                    # Find unprocessed logs
                    raw_logs = RawLog.objects.filter(is_parsed=False).order_by('id')[:self.logs_per_batch]
                    
                    log_count = 0
                    threat_count = 0
                    new_threats = [] # Track new threats for this run
                    
                    # Process each log with the detailed analysis
                    for raw_log in raw_logs:
                        try:
                            # Use the full threat analysis - NOT the simple version
                            from authentication.views_settings import create_parsed_log_from_raw
                            
                            # Process the log with detailed threat analysis
                            parsed_log = create_parsed_log_from_raw(raw_log)
                            
                            if parsed_log:
                                log_count += 1
                                # Count threats
                                if parsed_log.status in ['suspicious', 'attack']:
                                    # Generate a signature for deduplication
                                    threat_signature = self._get_threat_signature(parsed_log)
                                    
                                    # Only count as new if we haven't alerted on this signature
                                    if threat_signature not in self.alerted_threats:
                                        threat_count += 1
                                        new_threats.append(parsed_log)
                                        self.alerted_threats.add(threat_signature)
                                
                                # Log the processing
                                logger.info(f"Processing parsed log ID {parsed_log.id} for reporting")
                                
                        except Exception as e:
                            logger.error(f"Error processing log {raw_log.id}: {str(e)}")
                            # Mark as processed to avoid retry
                            raw_log.is_parsed = True
                            raw_log.save()
                    
                    # Update the dashboard counts
                    if log_count > 0:
                        logger.info(f"Real-time analysis processed {log_count} logs, found {threat_count} potential threats")
                        self.force_refresh_dashboard()
                        
                        # Create report for NEW significant findings only
                        if threat_count > 0:
                            self._create_threat_report(threat_count, new_threats)
                    
                    # Schedule the next run based on user settings
                    next_run_time = timezone.now() + timezone.timedelta(seconds=self.processing_interval)
                
                # Sleep for a short time to be responsive
                time.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Error in continuous processing: {str(e)}")
                # Still calculate next run time to avoid tight looping after an error
                next_run_time = timezone.now() + timezone.timedelta(seconds=self.processing_interval)
                time.sleep(5)  # Longer sleep on error

    def _get_threat_signature(self, parsed_log):
        """Generate a unique signature for a threat to avoid duplicate alerts"""
        components = []
        
        # Include key identifying information
        if parsed_log.source_ip:
            components.append(f"ip:{parsed_log.source_ip}")
            
        if parsed_log.status:
            components.append(f"status:{parsed_log.status}")
            
        if hasattr(parsed_log, 'request_path') and parsed_log.request_path:
            components.append(f"path:{parsed_log.request_path}")
            
        # Add data from normalized_data if available
        if hasattr(parsed_log, 'normalized_data') and parsed_log.normalized_data:
            nd = parsed_log.normalized_data
            
            # Add attack type if available
            if 'analysis' in nd and 'attack_type' in nd['analysis']:
                components.append(f"attack:{nd['analysis']['attack_type']}")
                
            # Add threat details as part of signature
            if 'analysis' in nd and 'threat_details' in nd['analysis']:
                details = nd['analysis']['threat_details']
                if details and isinstance(details, list) and len(details) > 0:
                    components.append(f"detail:{details[0]}")
        
        # Create a signature string and hash it
        signature_str = "|".join(components)
        
        import hashlib
        return hashlib.md5(signature_str.encode('utf-8')).hexdigest()

    def _check_log_files_for_new_content(self):
        """Actively check log files for new content and create raw logs"""
        try:
            # Check each source
            for source_id, info in list(self.file_positions.items()):
                source = info['source']
                file_path = info['path']
                last_pos = info['position']
                
                if not os.path.exists(file_path):
                    continue
                    
                try:
                    current_size = os.path.getsize(file_path)
                    
                    # New content available?
                    if current_size > last_pos:
                        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
                            # Seek to the last position
                            file.seek(last_pos)
                            
                            # Read new content
                            new_content = file.read()
                            
                            if new_content.strip():
                                # Process new content line by line
                                lines = new_content.splitlines()
                                logger.info(f"Read {len(lines)} new lines from {file_path}")
                                
                                # Create raw logs in transaction
                                with transaction.atomic():
                                    for line in lines:
                                        if line.strip():
                                            # Extract timestamp from log content
                                            log_timestamp = timezone.now()  # Default fallback
                                            
                                            # For Apache logs
                                            if source.source_type.lower() in ('apache', 'apache_access'):
                                                timestamp_match = re.search(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\]', line)
                                                if timestamp_match:
                                                    try:
                                                        time_str = timestamp_match.group(1)
                                                        parsed_time = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
                                                        log_timestamp = parsed_time
                                                    except Exception as e:
                                                        logger.debug(f"Failed to parse Apache timestamp: {e}")
                                            
                                            # For MySQL logs
                                            elif source.source_type.lower() in ('mysql', 'mysql_error'):
                                                timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})', line)
                                                if timestamp_match:
                                                    try:
                                                        time_str = timestamp_match.group(1)
                                                        parsed_time = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
                                                        # Make timezone-aware
                                                        if timezone.is_naive(parsed_time):
                                                            parsed_time = timezone.make_aware(parsed_time)
                                                        log_timestamp = parsed_time
                                                    except Exception as e:
                                                        logger.debug(f"Failed to parse MySQL timestamp: {e}")
                                            
                                            # Create RawLog entry with extracted timestamp
                                            RawLog.objects.create(
                                                source=source,
                                                content=line.strip(),
                                                timestamp=log_timestamp,  # Use extracted timestamp
                                                is_parsed=False
                                            )
                        
                        # Update file position
                        info['position'] = current_size
                        info['last_read'] = timezone.now()
                        
                        # Update database position
                        LogFilePosition.objects.update_or_create(
                            source=source,
                            defaults={
                                'position': current_size,
                                'last_read': timezone.now()
                            }
                        )
                except Exception as e:
                    logger.error(f"Error reading file {file_path}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error checking log files: {str(e)}")

    def _create_threat_report(self, threat_count, new_threats):
        """Create a threat report for newly detected threats"""
        try:
            if not new_threats:
                return
                
            # Group threats by their source (which is tied to a specific user)
            threats_by_source = {}
            for threat in new_threats:
                # Get the source ID from the raw log this threat was created from
                source_id = None
                if hasattr(threat, 'raw_log') and threat.raw_log:
                    source_id = threat.raw_log.source_id
                
                if source_id not in threats_by_source:
                    threats_by_source[source_id] = []
                threats_by_source[source_id].append(threat)
            
            # Process each source's threats separately
            for source_id, source_threats in threats_by_source.items():
                try:
                    # Get the log source
                    from .models import LogSource
                    source = LogSource.objects.get(id=source_id)
                    
                    # Find user to notify (using LogSource.owner if it exists)
                    from django.contrib.auth import get_user_model
                    User = get_user_model()
                    
                    # First check if we have owner field on LogSource model
                    user = None
                    if hasattr(source, 'owner'):
                        user = source.owner
                    elif hasattr(source, 'user'):
                        user = source.user
                    else:
                        # Fallback to most recently active user
                        user = User.objects.filter(is_active=True).order_by('-last_login').first()
                        
                    if not user:
                        logger.error(f"No user found for log source {source.name} (ID: {source_id})")
                        continue
                    
                    # Count by severity for this source
                    severity_counts = {
                        'attack': sum(1 for t in source_threats if t.status == 'attack'),
                        'suspicious': sum(1 for t in source_threats if t.status == 'suspicious')
                    }
                    
                    # Get IPs involved for this source
                    ip_addresses = set()
                    for threat in source_threats:
                        if threat.source_ip:
                            ip_addresses.add(threat.source_ip)
                            
                    # Get examples for this source
                    examples = []
                    for threat in source_threats[:5]:  # First 5 threats
                        if hasattr(threat, 'request_path') and threat.request_path:
                            examples.append(f"{threat.status.upper()} on path: {threat.request_path[:50]}...")
                        elif hasattr(threat, 'normalized_data') and threat.normalized_data:
                            if 'analysis' in threat.normalized_data and 'attack_type' in threat.normalized_data['analysis']:
                                examples.append(f"{threat.status.upper()}: {threat.normalized_data['analysis']['attack_type']}")
                            else:
                                examples.append(f"{threat.status.upper()}: {threat.source_ip or 'Unknown source'}")
                    
                    # Generate unique ID for this report
                    import hashlib
                    report_id = int(hashlib.md5(f"{source_id}-{','.join(sorted(ip_addresses))}-{timezone.now().isoformat()}".encode()).hexdigest()[:8], 16) % 1000000
                    
                    # Create unique signature for deduplication
                    alert_signature = f"{user.id}-{source_id}-{report_id}"
                    
                    # Check if we've sent this alert recently (deduplication)
                    from authentication.models import SystemSettings
                    import json
                    
                    # Get/create alert tracking record
                    sent_alerts_key = f"user_{user.id}_alerts"
                    alert_tracking, created = SystemSettings.objects.get_or_create(
                        section='alert_tracking',
                        settings_key=sent_alerts_key,
                        defaults={'settings_value': '{}'}
                    )
                    
                    # Load sent alerts for this user
                    try:
                        user_alerts = json.loads(alert_tracking.settings_value)
                    except (json.JSONDecodeError, TypeError):
                        user_alerts = {}
                        
                    # Check if sent within last hour
                    current_time = timezone.now().timestamp()
                    if alert_signature in user_alerts and (current_time - user_alerts[alert_signature]) < 3600:  # 1 hour
                        logger.info(f"Skipping duplicate alert {alert_signature} for user {user.username}")
                        continue
                        
                    # Record this alert
                    user_alerts[alert_signature] = current_time
                    alert_tracking.settings_value = json.dumps(user_alerts)
                    alert_tracking.save()
                    
                    # Send alert to this user for their log source
                    from alerts.services import AlertService
                    AlertService.send_alert(
                        title=f"Security Alert for {source.name}: {len(source_threats)} threats detected",
                        message=(
                            f"Real-time analysis detected {severity_counts['attack']} attacks and "
                            f"{severity_counts['suspicious']} suspicious activities.\n\n"
                            f"IP Addresses involved: {', '.join(ip_addresses)}\n\n"
                            f"Examples:\n- " + "\n- ".join(examples) + "\n\n"
                            f"These events were detected just now and require investigation."
                        ),
                        severity='high' if severity_counts['attack'] > 0 else 'medium',
                        threat_id=report_id,
                        source_ip=",".join(list(ip_addresses)[:5]) if ip_addresses else None,
                        affected_system=source.name,
                        user=user  # Include the user parameter!
                    )
                    
                    logger.info(f"Sent threat notification to user {user.username} for source {source.name}")
                    
                except LogSource.DoesNotExist:
                    logger.error(f"Log source with ID {source_id} not found")
                except Exception as source_error:
                    logger.error(f"Error processing threats for source {source_id}: {str(source_error)}")
                
        except Exception as e:
            logger.error(f"Error creating threat report: {str(e)}")
            
    def force_refresh_dashboard(self):
        """Force refresh dashboard log count when new logs are detected, with time filtering"""
        try:
            from django.db.models import Count
            from django.core.cache import cache
            from datetime import timedelta
            
            now = timezone.now()
            
            # Calculate count for different time periods
            time_periods = {
                '1h': now - timedelta(hours=1),
                '3h': now - timedelta(hours=3),
                '12h': now - timedelta(hours=12),
                '1d': now - timedelta(days=1),
                '7d': now - timedelta(days=7),
                '30d': now - timedelta(days=30),
            }
            
            # Total counts (unfiltered)
            raw_total = RawLog.objects.count()
            parsed_total = ParsedLog.objects.count()
            threat_total = ParsedLog.objects.filter(status__in=['suspicious', 'attack']).count()
            
            # Store total counts in cache
            cache.set('log_count_raw', raw_total, 60)
            cache.set('log_count_parsed', parsed_total, 60)
            cache.set('log_count_threats', threat_total, 60)
            
            # Store filtered counts for each time period
            for period_key, start_time in time_periods.items():
                try:
                    # Count logs in this time period
                    raw_count = RawLog.objects.filter(timestamp__gte=start_time).count()
                    parsed_count = ParsedLog.objects.filter(timestamp__gte=start_time).count()
                    threat_count = ParsedLog.objects.filter(
                        timestamp__gte=start_time, 
                        status__in=['suspicious', 'attack']
                    ).count()
                    
                    # Store in cache with period-specific keys
                    cache.set(f'log_count_raw_{period_key}', raw_count, 60)
                    cache.set(f'log_count_parsed_{period_key}', parsed_count, 60)
                    cache.set(f'log_count_threats_{period_key}', threat_count, 60)
                except Exception as e:
                    logger.error(f"Error calculating counts for period {period_key}: {e}")
            
            # Report the 24h counts in logs for reference
            period_24h = '1d'
            raw_24h = cache.get(f'log_count_raw_{period_24h}') or 0
            threat_24h = cache.get(f'log_count_threats_{period_24h}') or 0
            
            logger.info(f"Refreshed dashboard counts: {raw_total} total raw logs, {raw_24h} in last 24h, {threat_total} total threats, {threat_24h} in last 24h")
            return True
        except Exception as e:
            logger.error(f"Error refreshing dashboard counts: {str(e)}")
            return False
            
    def stop(self):
        """Stop the real-time log processor"""
        if not self.running:
            logger.info("Real-time log processor is not running")
            return
            
        logger.info("Stopping real-time log processor")
        self.running = False
        
        if self.collection_manager:
            self.collection_manager.stop_monitoring()
        
        # Wait for threads to terminate
        if self.thread:
            self.thread.join(timeout=5)
            
        if self.file_watch_thread:
            self.file_watch_thread.join(timeout=5)
        
        logger.info("Real-time log processor stopped")
    
    def restart(self):
        """Restart the log processor by stopping and starting it again"""
        try:
            # Stop the processor if it's running
            self.stop()
            
            # Brief delay to ensure clean shutdown
            time.sleep(1)  
            
            # Reload user settings before starting
            self._load_user_settings()
            
            # Start again with the latest settings
            success = self.start()
            
            if success:
                logger.info("Log processor successfully restarted")
                return True
            else:
                logger.error("Failed to restart log processor")
                return False
        except Exception as e:
            logger.error(f"Error during log processor restart: {str(e)}", exc_info=True)
            return False
            
    def clear_alert_history(self):
        """Clear the alert deduplication history to start alerting on threats again"""
        self.alerted_threats = set()
        logger.info("Alert deduplication history cleared")
        
    def _create_default_sources(self):
        """Create default log sources if none exist"""
        defaults = []
        
        try:
            # Default Apache log
            apache_path = r"C:\xampp\apache\logs\access.log" if os.name == 'nt' else "/var/log/apache2/access.log"
            apache_source, created = LogSource.objects.get_or_create(
                name="Apache Web Server",
                defaults={
                    'source_type': "apache",
                    'file_path': apache_path,
                    'enabled': True
                }
            )
            if created:
                defaults.append(apache_source)
                
            # Default MySQL log
            mysql_path = r"C:\xampp\mysql\data\mysql_error.log" if os.name == 'nt' else "/var/log/mysql/mysql.log"
            mysql_source, created = LogSource.objects.get_or_create(
                name="MySQL Database Server",
                defaults={
                    'source_type': "mysql",
                    'file_path': mysql_path,
                    'enabled': True
                }
            )
            if created:
                defaults.append(mysql_source)
                
            return defaults
        except Exception as e:
            logger.error(f"Error creating default log sources: {str(e)}")
            return []