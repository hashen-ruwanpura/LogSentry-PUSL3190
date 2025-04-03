import os
import time
import glob
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from django.utils import timezone
from django.conf import settings
from .models import LogSource, LogFilePosition, RawLog
from .parsers import LogParserFactory

class LogFileHandler(FileSystemEventHandler):
    """Handler for monitoring log file changes"""
    
    def __init__(self, log_source):
        self.log_source = log_source
        self.parser = LogParserFactory.get_parser(log_source.source_type)
    
    def on_modified(self, event):
        if not event.is_directory and event.src_path == self.log_source.file_path:
            self._process_log_file(event.src_path)
    
    def _process_log_file(self, file_path):
        """Process new lines in the log file"""
        # Get file position from database or start from beginning
        position = self._get_last_position(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(position)
                batch = []
                
                for line in f:
                    line = line.strip()
                    if line:
                        # Create raw log entry
                        raw_log = RawLog(
                            source=self.log_source,
                            content=line,
                            timestamp=timezone.now()
                        )
                        batch.append(raw_log)
                
                # Bulk create raw logs
                if batch:
                    RawLog.objects.bulk_create(batch)
                    
                    # Parse all created logs
                    for log in batch:
                        self.parser.parse(log)
                
                # Save new position
                self._save_position(file_path, f.tell())
                
        except (IOError, PermissionError) as e:
            print(f"Error reading log file {file_path}: {str(e)}")
    
    def _get_last_position(self, file_path):
        """Get the last read position for this file"""
        try:
            position_obj = LogFilePosition.objects.get(
                source=self.log_source, 
                file_path=file_path
            )
            return position_obj.position
        except LogFilePosition.DoesNotExist:
            return 0
    
    def _save_position(self, file_path, position):
        """Save the current read position"""
        LogFilePosition.objects.update_or_create(
            source=self.log_source,
            file_path=file_path,
            defaults={'position': position, 'last_updated': timezone.now()}
        )

class LogCollectionManager:
    """Manager for log collection processes"""
    
    def __init__(self):
        self.observer = None
        self.handlers = {}
    
    def start_monitoring(self):
        """Start monitoring all enabled log sources"""
        if self.observer and self.observer.is_alive():
            return False
            
        self.observer = Observer()
        
        # Get all enabled log sources
        log_sources = LogSource.objects.filter(enabled=True)
        
        for source in log_sources:
            if not os.path.exists(source.file_path):
                print(f"Warning: Log file {source.file_path} does not exist. Skipping.")
                continue
                
            # Create and register handler
            handler = LogFileHandler(source)
            self.handlers[source.id] = handler
            
            # Watch directory containing the file
            directory = os.path.dirname(source.file_path)
            self.observer.schedule(handler, directory, recursive=False)
            
            # Process existing content
            handler._process_log_file(source.file_path)
        
        self.observer.start()
        return True
    
    def stop_monitoring(self):
        """Stop the log monitoring"""
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
            self.observer = None
            self.handlers = {}
            return True
        return False
    
    def reload_sources(self):
        """Reload log sources (stop and restart monitoring)"""
        self.stop_monitoring()
        return self.start_monitoring()

# Create a singleton instance
log_manager = LogCollectionManager()