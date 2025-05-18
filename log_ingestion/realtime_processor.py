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
from django.db.utils import OperationalError
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
            # Save alerted threats before stopping
            temp_alerted_threats = self.alerted_threats.copy()
            self.stop()
            time.sleep(1)  # Give time to clean up
            # Restore alerted threats
            self.alerted_threats = temp_alerted_threats
    
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
                
                # CRITICAL: ALWAYS get the CURRENT file size to start from the END
                current_file_size = os.path.getsize(source.file_path)
                
                # Clean up any duplicate positions before initializing
                self._clean_duplicate_positions(source)
                
                # Update or create position record in memory
                self.file_positions[source.id] = {
                    'source': source,
                    'path': source.file_path,
                    'position': current_file_size,  # Always start from the current end
                    'last_updated': timezone.now()  # Changed from 'last_read' to 'last_updated'
                }
                
                # Get existing position record (there should be only one after cleanup)
                try:
                    position = LogFilePosition.objects.get(source=source)
                    
                    # IMPORTANT: Always update to current file size to ensure we only process new content
                    old_position = position.position
                    position.position = current_file_size
                    position.last_updated = timezone.now()
                    position.save()
                    
                    if old_position != current_file_size:
                        logger.info(f"Updated file position for {source.name}: {old_position} -> {current_file_size}")
                except LogFilePosition.DoesNotExist:
                    # Create new position record starting at the END of file
                    position = LogFilePosition.objects.create(
                        source=source,
                        position=current_file_size,
                        last_updated=timezone.now()
                    )
                    logger.info(f"Created new file position for {source.name} at end: {current_file_size}")
                except LogFilePosition.MultipleObjectsReturned:
                    # This shouldn't happen after cleanup, but just in case
                    logger.warning(f"Multiple positions still exist for {source.name}. Cleaning up again...")
                    self._clean_duplicate_positions(source)
        
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
        
        # Initialize a content deduplication cache
        content_hashes = {}
        
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
                                                # Deduplicate by content hash
                                                import hashlib
                                                content_hash = hashlib.md5(line.strip().encode('utf-8')).hexdigest()
                                                
                                                # Skip if we've seen this exact content in the last hour
                                                cache_key = f"raw_log:{content_hash}"
                                                if content_hash in content_hashes:
                                                    continue
                                                    
                                                # Remember this content hash for an hour
                                                content_hashes[content_hash] = timezone.now()
                                                
                                                # Create RawLog entry with timezone-aware timestamp
                                                RawLog.objects.create(
                                                    source=source,
                                                    content=line.strip(),
                                                    timestamp=timezone.now(),
                                                    is_parsed=False
                                                )
                                    
                                    # Update file position
                                    info['position'] = current_size
                                    info['last_updated'] = timezone.now()
                                    
                                    # Update database position
                                    LogFilePosition.objects.update_or_create(
                                        source=source,
                                        defaults={
                                            'position': current_size,
                                            'last_updated': timezone.now()  # Changed from 'last_read' to 'last_updated'
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
                                'last_updated': timezone.now()  # Changed from 'last_read' to 'last_updated'
                            }
                        )
                
                # Short sleep between checks to reduce CPU usage
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in file monitoring: {str(e)}")
                time.sleep(5)  # Longer sleep on error
    
    def _continuous_processing(self):
        """Continuous log processing loop that properly analyzes logs from all sources with priority"""
        logger.info("Starting enhanced continuous log processing with Apache prioritization")
        
        next_run_time = timezone.now()
        last_processed_id = 0  # Track the last processed log ID
        
        while self.running and self.enabled:
            try:
                current_time = timezone.now()
                
                # Check if it's time to run the analysis and we're enabled
                if current_time >= next_run_time and self.enabled:
                    # Always reset file positions to the current end before starting a new cycle
                    self._reset_file_positions_to_end()
                    
                    # MODIFIED: Add a timestamp filter to only process recent logs
                    cutoff_time = timezone.now() - timezone.timedelta(hours=1)
                    
                    # PRIORITIZATION: First fetch and process a minimum number of Apache logs
                    apache_logs = RawLog.objects.filter(
                        is_parsed=False,
                        source__source_type__startswith='apache',
                        timestamp__gte=cutoff_time,  # Only process recent logs
                        id__gt=last_processed_id
                    ).order_by('-timestamp')[:max(10, self.logs_per_batch // 3)]  # Use -timestamp to get newest first
                    
                    # Then fetch remaining logs up to the batch limit, prioritizing newer logs
                    remaining_quota = max(0, self.logs_per_batch - apache_logs.count())
                    if remaining_quota > 0:
                        # FIXED: Materialize the apache logs IDs to avoid MariaDB's limitation
                        apache_log_ids = list(apache_logs.values_list('id', flat=True))
                        
                        other_logs = RawLog.objects.filter(
                            is_parsed=False,
                            timestamp__gte=cutoff_time,  # Only process recent logs
                            id__gt=last_processed_id
                        ).exclude(
                            id__in=apache_log_ids  # Use the materialized list instead of the queryset
                        ).order_by('-timestamp')[:remaining_quota]  # Use -timestamp to get newest first
                    else:
                        other_logs = RawLog.objects.none()
                    
                    # Combine the logs, with Apache first
                    raw_logs = list(apache_logs) + list(other_logs)
                    
                    log_count = 0
                    threat_count = 0
                    new_threats = [] # Track new threats for this run
                    max_processed_id = last_processed_id  # Track highest ID processed this cycle
                    apache_count = 0  # Count Apache logs processed
                    mysql_count = 0   # Count MySQL logs processed
                    
                    # Process each log with the detailed analysis
                    for raw_log in raw_logs:
                        try:
                            # Update max ID seen
                            if raw_log.id > max_processed_id:
                                max_processed_id = raw_log.id
                        
                            # Track log source types
                            if raw_log.source and raw_log.source.source_type.startswith('apache'):
                                apache_count += 1
                            elif raw_log.source and 'mysql' in raw_log.source.source_type:
                                mysql_count += 1
                                
                            # Use the full threat analysis - NOT the simple version
                            from authentication.views_settings import create_parsed_log_from_raw
                        
                            # Process the log with detailed threat analysis
                            parsed_log = create_parsed_log_from_raw(raw_log)

                            if parsed_log:
                                # Log the processing - MOVED INSIDE THE IF BLOCK
                                logger.info(f"Processing parsed log ID {parsed_log.id} for reporting")
                                
                                log_count += 1
                                # Count threats
                                if parsed_log.status in ['suspicious', 'attack']:
                                    # ENHANCED: Extract MITRE data from normalized_data
                                    mitre_tactic = None
                                    mitre_technique = None
                                    
                                    if hasattr(parsed_log, 'normalized_data') and parsed_log.normalized_data:
                                        analysis_data = parsed_log.normalized_data.get('analysis', {})
                                        mitre_tactic = analysis_data.get('mitre_tactic')
                                        mitre_technique = analysis_data.get('mitre_technique')
                                        mitre_tactic_id = analysis_data.get('mitre_tactic_id')
                                        mitre_technique_id = analysis_data.get('mitre_technique_id')
                                        
                                        # If we have MITRE data, create or update the Threat record
                                        if parsed_log.status == 'attack' or parsed_log.status == 'suspicious':
                                            try:
                                                from threat_detection.models import Threat
                                                
                                                # Create threat with enhanced MITRE information
                                                threat = Threat.objects.create(
                                                    severity="high" if parsed_log.status == 'attack' else "medium",
                                                    status="new",
                                                    description=f"Detected {analysis_data.get('attack_type', 'unknown attack')} in {parsed_log.request_path or 'log entry'}",
                                                    source_ip=parsed_log.source_ip,
                                                    affected_system=parsed_log.source_type,
                                                    mitre_tactic=mitre_tactic,
                                                    mitre_technique=f"{mitre_technique} ({mitre_technique_id})" if mitre_technique and mitre_technique_id else mitre_technique,
                                                    created_at=timezone.now(),
                                                    updated_at=timezone.now(),
                                                    parsed_log=parsed_log,
                                                    analysis_data={
                                                        "attack_type": analysis_data.get('attack_type'),
                                                        "attack_score": analysis_data.get('attack_score'),
                                                        "mitre_tactic": mitre_tactic,
                                                        "mitre_tactic_id": mitre_tactic_id,
                                                        "mitre_technique": mitre_technique,
                                                        "mitre_technique_id": mitre_technique_id,
                                                        "details": analysis_data.get('threat_details', [])
                                                    }
                                                )
                                                
                                                # Generate a signature for deduplication
                                                threat_signature = self._get_threat_signature(parsed_log)
                                                
                                                # Only count as new if we haven't alerted on this signature
                                                if threat_signature not in self.alerted_threats:
                                                    threat_count += 1
                                                    new_threats.append(threat)  # Note: Changed from parsed_log to threat
                                                    self.alerted_threats.add(threat_signature)
                                            except Exception as threat_error:
                                                logger.error(f"Error creating threat: {str(threat_error)}")
                            
                        except Exception as e:
                            logger.error(f"Error processing log {raw_log.id}: {str(e)}")
                            # Mark as processed to avoid retry
                            raw_log.is_parsed = True
                            raw_log.save()
                
                    # Update the last processed ID for next cycle
                    if max_processed_id > last_processed_id:
                        last_processed_id = max_processed_id
                
                    # Update the dashboard counts
                    if log_count > 0:
                        logger.info(f"Real-time analysis processed {log_count} logs ({apache_count} Apache, {mysql_count} MySQL), found {threat_count} potential threats")
                        self.force_refresh_dashboard()
                        
                        # Create report for NEW significant findings only
                        if threat_count > 0:
                            self._create_threat_report(threat_count, new_threats)
                
                # IMPORTANT: Calculate next run time based on CURRENT time
                # This ensures intervals are properly respected regardless of processing time
                next_run_time = timezone.now() + timezone.timedelta(seconds=self.processing_interval)
                logger.info(f"Next scheduled processing in {self.processing_interval} seconds at {next_run_time}")
                
                # FIXED: Sleep for a short time to be responsive but not consume CPU
                # Calculate sleep time to prevent busy waiting
                sleep_time = 0.5
                if next_run_time > timezone.now():
                    sleep_time = min(5.0, max(0.5, (next_run_time - timezone.now()).total_seconds() / 2))
                time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Error in continuous processing: {str(e)}")
                # Still calculate next run time to avoid tight looping after an error
                next_run_time = timezone.now() + timezone.timedelta(seconds=self.processing_interval)
                time.sleep(5)  # Longer sleep on error

    def _get_threat_signature(self, parsed_log):
        """Generate a more robust signature for a threat to avoid duplicate alerts"""
        components = []
        
        # Add source IP as primary component for deduplication
        if parsed_log.source_ip:
            components.append(f"ip:{parsed_log.source_ip}")
        
        # Add attack path - crucial for identifying unique attacks
        if hasattr(parsed_log, 'request_path') and parsed_log.request_path:
            # Only use the base path without query parameters for better deduplication
            base_path = parsed_log.request_path.split('?')[0]
            components.append(f"path:{base_path}")
        
        # Add attack type if available - key for deduplication
        if hasattr(parsed_log, 'normalized_data') and parsed_log.normalized_data:
            nd = parsed_log.normalized_data
            if 'analysis' in nd and 'attack_type' in nd['analysis']:
                components.append(f"attack:{nd['analysis']['attack_type']}")
        
        # Add status (attack/suspicious) for better categorization
        if parsed_log.status:
            components.append(f"status:{parsed_log.status}")
            
        # Include timestamp rounded to 1 hour to prevent duplicates within same hour
        if hasattr(parsed_log, 'timestamp') and parsed_log.timestamp:
            # Round timestamp to hourly intervals (3600s) for time-based deduplication
            ts = int(parsed_log.timestamp.timestamp() // 3600) * 3600
            components.append(f"time:{ts}")
        
        # Create a signature string and hash it
        signature_str = "|".join([c for c in components if c])  # Filter out any empty components
        
        import hashlib
        return hashlib.md5(signature_str.encode('utf-8')).hexdigest()

    def _check_log_files_for_new_content(self):
        """Active monitoring of log files with improved filtering"""
        try:
            for source_id, info in list(self.file_positions.items()):
                source = info['source']
                file_path = info['path']
                
                # Skip processing if this is a MySQL log and it's being processed too often
                if source.source_type.lower() in ('mysql', 'mysql_error'):
                    # Check last processed time for this MySQL source
                    last_mysql_check = getattr(self, '_last_mysql_check', {}).get(source_id, 0)
                    current_time = time.time()
                    
                    # Only process MySQL logs every 5 seconds to avoid overwhelming the system
                    if current_time - last_mysql_check < 5:  # 5-second throttle for MySQL logs
                        continue
                    
                    # Update last check time
                    if not hasattr(self, '_last_mysql_check'):
                        self._last_mysql_check = {}
                    self._last_mysql_check[source_id] = current_time
                
                # Rest of the method remains the same...
                if not os.path.exists(file_path):
                    continue
                    
                try:
                    current_size = os.path.getsize(file_path)
                    
                    # New content available?
                    if current_size > info['position']:
                        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
                            # Seek to the last position
                            file.seek(info['position'])
                            
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
                                            
                                            # For MySQL error logs, check whitelist patterns first
                                            should_skip = False
                                            if source.source_type.lower() in ('mysql', 'mysql_error'):
                                                # MySQL error patterns to whitelist
                                                mysql_whitelist_patterns = [
                                                    "Incorrect definition of table mysql",
                                                    "expected column .* at position",
                                                    "InnoDB: Initializing buffer pool",
                                                    "InnoDB: Completed initialization",
                                                    "Server socket created on IP",
                                                    "Starting MariaDB",
                                                    "ready for connections",
                                                    "InnoDB: Starting shutdown"
                                                ]
                                                
                                                for pattern in mysql_whitelist_patterns:
                                                    if re.search(pattern, line, re.IGNORECASE):
                                                        logger.debug(f"Skipping whitelisted MySQL message: {line[:50]}...")
                                                        should_skip = True
                                                        break

                                            # Only process if not skipped
                                            if not should_skip:
                                                # Create RawLog entry with extracted timestamp
                                                RawLog.objects.create(
                                                    source=source,
                                                    content=line.strip(),
                                                    timestamp=log_timestamp,  # Use extracted timestamp
                                                    is_parsed=False
                                                )
                        
                        # Update file position
                        info['position'] = current_size
                        info['last_updated'] = timezone.now()
                        
                        # Update database position
                        LogFilePosition.objects.update_or_create(
                            source=source,
                            defaults={
                                'position': current_size,
                                'last_updated': timezone.now()  # Changed from 'last_read' to 'last_updated'
                            }
                        )
                except Exception as e:
                    logger.error(f"Error reading file {file_path}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error checking log files: {str(e)}")

    def _create_threat_report(self, threat_count, new_threats):
        """Create a threat report with improved deduplication"""
        try:
            if not new_threats:
                return
                
            # Verify the AlertService is available
            try:
                from alerts.services import AlertService
            except ImportError:
                logger.error("Failed to import AlertService - alerts will not be sent!")
                return
                
            # Load current deduplication cache from database for persistence
            from authentication.models import SystemSettings
            import json
            
            dedup_setting, created = SystemSettings.objects.get_or_create(
                section='alert_deduplication',
                settings_key='alert_signatures',
                defaults={'settings_value': '{}'}
            )
            
            try:
                dedup_cache = json.loads(dedup_setting.settings_value)
            except (json.JSONDecodeError, TypeError):
                dedup_cache = {}
                
            # Current time for expiring old entries
            current_time = timezone.now().timestamp()
            
            # Clean up old entries (older than 3 hours - extending from 1 hour)
            expired_keys = [k for k, v in dedup_cache.items() if current_time - v > 10800]  # 3 hours
            for key in expired_keys:
                del dedup_cache[key]
            
            # Initialize processed_paths to track multiple alerts for same path
            processed_paths = set()
            
            # Group threats that need alerts (with improved deduplication)
            alerts_to_send = []
            for threat in new_threats:
                # Generate signature for this threat
                signature = self._get_threat_signature(threat)
                
                # Skip if sent in the last three hours
                if signature in dedup_cache and (current_time - dedup_cache[signature]) < 10800:  # 3 hours
                    logger.info(f"Skipping duplicate alert for signature {signature[:8]}")
                    continue
                    
                # Additional deduplication based on request path
                if hasattr(threat, 'parsed_log') and hasattr(threat.parsed_log, 'request_path'):
                    path = threat.parsed_log.request_path
                    if path:
                        path_key = f"{threat.source_ip}:{path.split('?')[0]}"
                        if path_key in processed_paths:
                            logger.info(f"Skipping duplicate path {path_key}")
                            continue
                        processed_paths.add(path_key)
                        
                # Mark as alerted
                dedup_cache[signature] = current_time
                alerts_to_send.append(threat)
            
            # Save updated deduplication cache
            dedup_setting.settings_value = json.dumps(dedup_cache)
            dedup_setting.save()
            
            # Continue with sending alerts for new threats only
            if not alerts_to_send:
                logger.info("All new threats were duplicates of recent alerts - no new alerts sent")
                return
                
            # Group remaining threats by source
            threats_by_source = {}
            for threat in alerts_to_send:
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
    
    def _clean_duplicate_positions(self, source):
        """Clean up duplicate LogFilePosition records for a source"""
        try:
            # Count positions for this source
            position_count = LogFilePosition.objects.filter(source=source).count()
            
            if position_count <= 1:
                return  # No duplicates
                
            logger.warning(f"Found {position_count} position records for source {source.name}. Cleaning up...")
            
            # Get all positions for this source ordered by last_read (newest first)
            positions = LogFilePosition.objects.filter(source=source).order_by('-last_updated', '-id')  # Changed from '-last_read'
            
            if positions.exists():
                # Keep only the most recent one
                most_recent = positions.first()
                
                # Delete all others
                positions.exclude(id=most_recent.id).delete()
                
                # Get current file size
                current_file_size = 0
                if os.path.exists(source.file_path):
                    current_file_size = os.path.getsize(source.file_path)
                
                # Always update the position to the end of the file
                most_recent.position = current_file_size
                most_recent.last_updated = timezone.now()
                most_recent.save()
                
                # Update memory cache
                if source.id in self.file_positions:
                    self.file_positions[source.id]['position'] = current_file_size
                    self.file_positions[source.id]['last_updated'] = timezone.now()  # Changed from 'last_read'
                
                logger.info(f"Cleaned up duplicate positions for {source.name}. Reset to end: {current_file_size}")
            
        except Exception as e:
            logger.error(f"Error cleaning up positions for {source.name}: {str(e)}")
            # As a last resort, delete all positions and create a new one at the end
            try:
                LogFilePosition.objects.filter(source=source).delete()
                
                if os.path.exists(source.file_path):
                    current_size = os.path.getsize(source.file_path)
                    LogFilePosition.objects.create(
                        source=source,
                        position=current_size,
                        last_updated=timezone.now()
                    )
                    logger.info(f"Emergency reset: Created new position at end ({current_size}) for {source.name}")
            except Exception as inner_e:
                logger.error(f"Failed emergency position reset for {source.name}: {str(inner_e)}")
    
    def _reset_file_positions_to_end(self):
        """Reset all file positions to the current end to ensure we only process new logs"""
        logger.info("Resetting all file positions to current end")
        
        for source in self.log_sources:
            try:
                # Skip invalid paths
                if not source.file_path or not os.path.exists(source.file_path):
                    continue
                
                # Get current file size
                current_file_size = os.path.getsize(source.file_path)
                
                # Clean up any duplicate positions
                self._clean_duplicate_positions(source)
                
                # Update memory cache
                if source.id in self.file_positions:
                    self.file_positions[source.id]['position'] = current_file_size
                    self.file_positions[source.id]['last_updated'] = timezone.now()
            
                # IMPORTANT: Force update database position to current end of file, with retries
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        with transaction.atomic():
                            LogFilePosition.objects.update_or_create(
                                source=source,
                                defaults={
                                    'position': current_file_size,
                                    'last_updated': timezone.now()
                                }
                            )
                        logger.info(f"Reset position for {source.name} to end of file: {current_file_size}")
                        break  # Success, exit retry loop
                    except OperationalError as oe:
                        if attempt < max_retries - 1:
                            logger.warning(f"Database lock timeout when resetting position for {source.name}. Retry {attempt+1}/{max_retries}")
                            time.sleep(1)
                        else:
                            raise
            except Exception as e:
                logger.error(f"Error resetting position for {source.name}: {str(e)}")
    
    def _get_deduplication_cache(self):
        """Get shared deduplication cache from database and memory"""
        from authentication.models import SystemSettings
        import json
        
        # Try memory cache first
        if hasattr(self, '_dedup_cache'):
            return self._dedup_cache
        
        # Otherwise load from database
        dedup_setting, created = SystemSettings.objects.get_or_create(
            section='alert_deduplication',
            settings_key='alert_signatures',
            defaults={'settings_value': '{}'}
        )
        
        try:
            self._dedup_cache = json.loads(dedup_setting.settings_value)
        except (json.JSONDecodeError, TypeError):
            self._dedup_cache = {}
            
        return self._dedup_cache

