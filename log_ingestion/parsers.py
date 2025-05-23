import re
import datetime
import ipaddress
import logging
from abc import ABC, abstractmethod
from django.utils import timezone
from .models import RawLog, ParsedLog

logger = logging.getLogger(__name__)

class BaseLogParser(ABC):
    def parse(self, raw_log):
        """Parse raw log and return normalized data"""
        try:
            # Handle both string content and RawLog objects
            if isinstance(raw_log, str):
                # If it's a string, create a temporary object with content attribute
                class TempRawLog:
                    def __init__(self, content_str):
                        self.content = content_str
                        self.timestamp = timezone.now()
                
                temp_log = TempRawLog(raw_log)
                return self._parse_raw_log(temp_log)
            else:
                # It's an actual RawLog or similar object
                return self._parse_raw_log(raw_log)
        except Exception as e:
            logger.error(f"Error in BaseLogParser.parse: {str(e)}")
            return None
    
    @abstractmethod
    def _parse_raw_log(self, raw_log):
        """The actual parsing implementation - subclasses must override"""
        pass
    
    def save_parsed_log(self, raw_log, normalized_data):
        """Save the parsed log data"""
        try:
            # Only try to create a database entry if it's a real RawLog object
            if hasattr(raw_log, 'id') and not isinstance(raw_log, str):
                parsed_log = ParsedLog(
                    raw_log=raw_log,
                    timestamp=normalized_data.get('timestamp', raw_log.timestamp),
                    normalized_data=normalized_data
                )
                
                # Extract common fields if available
                for field in ['log_level', 'source_ip', 'user_agent', 'request_method', 
                            'request_path', 'status_code', 'response_size', 'user_id',
                            'query', 'execution_time', 'source_type']:
                    if field in normalized_data:
                        setattr(parsed_log, field, normalized_data[field])
                
                parsed_log.save()
                
                # Mark raw log as parsed
                raw_log.is_parsed = True
                raw_log.save(update_fields=['is_parsed'])
                
                return parsed_log
            else:
                # For string or temp objects, just return the normalized data
                # This handles Kafka messages without database operations
                return normalized_data
        except Exception as e:
            logger.error(f"Error in save_parsed_log: {str(e)}")
            return None

class ApacheLogParser(BaseLogParser):
    """Parser for Apache access and error logs"""
    
    # Common log format regex
    COMMON_LOG_FORMAT_REGEX = r'(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (.+?) (\S+)" (\d{3}) (\d+|-)'
    
    # Combined log format regex (adds referrer and user agent)
    COMBINED_LOG_FORMAT_REGEX = COMMON_LOG_FORMAT_REGEX + r' "([^"]*)" "([^"]*)"'
    
    def _parse_raw_log(self, raw_log):
        """Parse Apache log entry - handles both RawLog objects and strings"""
        # Try combined format first
        combined_match = re.match(self.COMBINED_LOG_FORMAT_REGEX, raw_log.content)
        if combined_match:
            return self._parse_combined_log(combined_match, raw_log)
        
        # Try common format
        common_match = re.match(self.COMMON_LOG_FORMAT_REGEX, raw_log.content)
        if common_match:
            return self._parse_common_log(common_match, raw_log)
        
        # Error log format
        if raw_log.content.startswith('['):
            return self._parse_error_log(raw_log)
            
        # If we can't parse it, return basic metadata
        return self.save_parsed_log(raw_log, {
            'timestamp': getattr(raw_log, 'timestamp', timezone.now()),
            'raw_content': raw_log.content,
            'source_type': 'apache',
            'parse_success': False
        })
        
    def _parse_combined_log(self, match, raw_log):
        # Extract fields from combined log format
        ip, identd, userid, time_str, method, path, protocol, status, size, referrer, user_agent = match.groups()
        
        # Parse timestamp
        timestamp = datetime.datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
        
        # Create normalized data
        normalized_data = {
            'timestamp': timestamp,
            'source_ip': ip if self._is_valid_ip(ip) else None,
            'user_id': userid if userid != '-' else '',
            'request_method': method,
            'request_path': path,
            'protocol': protocol,
            'status_code': int(status) if status.isdigit() else None,
            'response_size': int(size) if size.isdigit() and size != '-' else 0,
            'referrer': referrer,
            'user_agent': user_agent,
            'log_type': 'apache_access',
            'parse_success': True
        }
        
        return self.save_parsed_log(raw_log, normalized_data)
    
    def _parse_common_log(self, match, raw_log):
        # Similar to _parse_combined_log but without referrer and user_agent
        ip, identd, userid, time_str, method, path, protocol, status, size = match.groups()
        
        # Parse timestamp
        timestamp = datetime.datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
        
        # Create normalized data
        normalized_data = {
            'timestamp': timestamp,
            'source_ip': ip if self._is_valid_ip(ip) else None,
            'user_id': userid if userid != '-' else '',
            'request_method': method,
            'request_path': path,
            'protocol': protocol,
            'status_code': int(status) if status.isdigit() else None,
            'response_size': int(size) if size.isdigit() and size != '-' else 0,
            'log_type': 'apache_access',
            'parse_success': True
        }
        
        return self.save_parsed_log(raw_log, normalized_data)
    
    def _parse_error_log(self, raw_log):
        # Basic error log parsing - actual implementation would be more complex
        content = raw_log.content
        
        # Try to extract timestamp and error level
        timestamp_match = re.search(r'\[(.*?)\]', content)
        timestamp_str = timestamp_match.group(1) if timestamp_match else None
        
        level_match = re.search(r'\[(error|warn|notice|info|debug)\]', content, re.IGNORECASE)
        log_level = level_match.group(1) if level_match else 'unknown'
        
        timestamp = None
        if timestamp_str:
            try:
                # Apache error logs often use this format
                timestamp = datetime.datetime.strptime(timestamp_str, '%a %b %d %H:%M:%S.%f %Y')
            except ValueError:
                pass
        
        normalized_data = {
            'timestamp': timestamp or raw_log.timestamp,
            'log_level': log_level,
            'message': content,
            'log_type': 'apache_error',
            'parse_success': True
        }
        
        return self.save_parsed_log(raw_log, normalized_data)
    
    def _is_valid_ip(self, ip):
        """Enhanced IP validation to reject reserved/private IPs if needed"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            logger.debug(f"Valid IP extracted: {ip}")
            return True
        except ValueError:
            logger.warning(f"Invalid IP format found: {ip}")
            return False

class MySQLLogParser(BaseLogParser):
    """Parser for MySQL general and slow query logs"""
    
    # Regex for MySQL timestamp format
    TIMESTAMP_REGEX = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z|\d{6}\s+\d{2}:\d{2}:\d{2})'
    
    # Regex for slow query log entry
    SLOW_QUERY_REGEX = r'# Time: (.*)\n# User@Host: (.*)\n# Query_time: (\d+\.\d+)\s+Lock_time: (\d+\.\d+)\s+Rows_sent: (\d+)\s+Rows_examined: (\d+)'
    
    def _parse_raw_log(self, raw_log):
        """Parse MySQL log entry - handles both RawLog objects and strings"""
        content = raw_log.content
        
        # Check if it's a slow query log
        slow_match = re.match(self.SLOW_QUERY_REGEX, content, re.DOTALL)
        if slow_match:
            return self._parse_slow_query(slow_match, raw_log)
        
        # Check for general log entry
        if re.match(self.TIMESTAMP_REGEX, content):
            return self._parse_general_log(raw_log)
        
        # Error log format usually starts with timestamp
        timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})', content)
        if timestamp_match:
            return self._parse_error_log(raw_log)
            
        # If we can't parse it, return basic metadata
        return self.save_parsed_log(raw_log, {
            'timestamp': getattr(raw_log, 'timestamp', timezone.now()),
            'raw_content': content,
            'source_type': 'mysql',
            'log_type': 'mysql_unknown',
            'parse_success': False
        })
        
    def _parse_slow_query(self, match, raw_log):
        time_str, user_host, query_time, lock_time, rows_sent, rows_examined = match.groups()
        
        # Extract query from the content (after the matched headers)
        content = raw_log.content
        query_start = content.find('SET timestamp=')
        query = content[query_start:] if query_start >= 0 else ""
        
        # Parse user@host
        user_match = re.match(r'(\w+)\[(\w+)\] @ ([\w\d\.-]+) \[([\d\.]+)\]', user_host)
        if user_match:
            user, db, hostname, ip = user_match.groups()
        else:
            user, db, hostname, ip = '', '', '', ''
        
        normalized_data = {
            'timestamp': raw_log.timestamp,  # Use the stored timestamp
            'user_id': user,
            'database': db,
            'host': hostname,
            'source_ip': ip if self._is_valid_ip(ip) else None,
            'query': query,
            'execution_time': float(query_time),
            'lock_time': float(lock_time),
            'rows_sent': int(rows_sent),
            'rows_examined': int(rows_examined),
            'log_type': 'mysql_slow_query',
            'parse_success': True
        }
        
        return self.save_parsed_log(raw_log, normalized_data)
    
    def _parse_general_log(self, raw_log):
        content = raw_log.content
        
        # Check for common MySQL log formats
        query_pattern = re.search(r'(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP).*?;', content, re.IGNORECASE | re.DOTALL)
        if query_pattern:
            query = query_pattern.group(0)
        else:
            # Try to extract queries after timestamp information
            query_parts = content.split(']')
            if len(query_parts) > 1:
                query = ']'.join(query_parts[1:]).strip()
            else:
                query = content  # Use entire content if no better extraction possible
        
        normalized_data = {
            'timestamp': raw_log.timestamp,
            'user_id': self._extract_user_id(content),
            'query': query,
            'log_type': 'mysql_general',
            'parse_success': True
        }
        
        return self.save_parsed_log(raw_log, normalized_data)
    
    def _parse_error_log(self, raw_log):
        content = raw_log.content
        
        # Extract timestamp and message
        timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})', content)
        timestamp_str = timestamp_match.group(1) if timestamp_match else None
        
        # Extract error level
        level_match = re.search(r'\b(ERROR|WARNING|NOTE|INFO)\b', content)
        log_level = level_match.group(1).lower() if level_match else 'unknown'
        
        # Extract message (everything after timestamp and level)
        message = content
        if timestamp_match:
            message = content[timestamp_match.end():].strip()
            if level_match:
                level_pos = message.find(level_match.group(0))
                if level_pos >= 0:
                    message = message[level_pos + len(level_match.group(0)):].strip()
        
        timestamp = None
        if timestamp_str:
            try:
                timestamp = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                pass
        
        normalized_data = {
            'timestamp': timestamp or raw_log.timestamp,
            'log_level': log_level,
            'message': message,
            'log_type': 'mysql_error',
            'parse_success': True
        }
        
        return self.save_parsed_log(raw_log, normalized_data)
    
    def _is_valid_ip(self, ip):
        """Check if string is a valid IP address"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            logger.debug(f"Valid IP extracted: {ip}")
            return True
        except ValueError:
            logger.warning(f"Invalid IP format found: {ip}")
            return False

    def _extract_user_id(self, content):
        """Extract user ID from MySQL log content"""
        user_match = re.search(r'User@Host:\s+(\w+)', content)
        if user_match:
            return user_match.group(1)
        
        # Try alternative format
        user_match = re.search(r'(\w+)\[[^\]]+\] @', content)
        if user_match:
            return user_match.group(1)
        
        return None

# Factory to get the correct parser based on log source type
class LogParserFactory:
    @staticmethod
    def get_parser(source_type):
        """Return the appropriate parser for the given source type"""
        if source_type in ['apache_access', 'apache_error']:
            return ApacheLogParser()
        elif source_type in ['mysql_general', 'mysql_slow', 'mysql_error']:
            return MySQLLogParser()
        else:
            raise ValueError(f"Unsupported log source type: {source_type}")