import re
import logging
from django.utils import timezone

logger = logging.getLogger(__name__)

class MitreAttackMapper:
    """
    Maps detected threats to the MITRE ATT&CK framework tactics and techniques
    based on threat characteristics and patterns
    """
    
    def __init__(self):
        # Initialize MITRE ATT&CK mappings
        self._initialize_mappings()
        
    def _initialize_mappings(self):
        """Initialize mappings between attack patterns and MITRE tactics/techniques"""
        # Format: 'pattern_type': ('tactic', 'technique_id', 'technique_name')
        self.sql_injection_mappings = {
            'default': ('initial_access', 'T1190', 'Exploit Public-Facing Application'),
            'authentication_bypass': ('defense_evasion', 'T1212', 'Exploitation for Credential Access'),
            'data_extraction': ('exfiltration', 'T1030', 'Data Transfer Size Limits')
        }
        
        self.xss_mappings = {
            'default': ('initial_access', 'T1189', 'Drive-by Compromise'),
            'stored': ('persistence', 'T1505.003', 'Web Shell'),
            'dom': ('execution', 'T1059.007', 'JavaScript')
        }
        
        self.command_injection_mappings = {
            'default': ('execution', 'T1059', 'T1059'),
            'web_shell': ('persistence', 'T1505.003', 'Web Shell'),
            'reverse_shell': ('command_and_control', 'T1071.001', 'Web Protocols')
        }
        
        self.path_traversal_mappings = {
            'default': ('discovery', 'T1083', 'File and Directory Discovery'),
            'sensitive_files': ('credential_access', 'T1552.001', 'Credentials In Files')
        }
        
        self.bruteforce_mappings = {
            'default': ('credential_access', 'T1110', 'Brute Force'),
            'password_spraying': ('credential_access', 'T1110.003', 'Password Spraying'),
            'credential_stuffing': ('credential_access', 'T1110.004', 'Credential Stuffing')
        }
        
        self.csrf_mappings = {
            'default': ('defense_evasion', 'T1527', 'Application Access Token'),
            'admin': ('privilege_escalation', 'T1068', 'Exploitation for Privilege Escalation'),
            'config': ('impact', 'T1565', 'Data Manipulation'),
            'import': ('execution', 'T1059', 'T1059'),
            'sql': ('execution', 'T1059.007', 'JavaScript/WebShell'),
            'export': ('exfiltration', 'T1030', 'Data Transfer Size Limits'),
            'server': ('discovery', 'T1082', 'System Information Discovery'),
            'database': ('credential_access', 'T1552', 'Unsecured Credentials')
        }
        
        self.session_hijacking_mappings = {
            'default': ('credential_access', 'T1539', 'Steal Web Session Cookie')
        }
        
        self.unauthorized_access_mappings = {
            'default': ('initial_access', 'T1078', 'Valid Accounts')
        }
        
        self.rate_limit_mappings = {
            'default': ('impact', 'T1499', 'Endpoint Denial of Service')
        }
        
        # Map rule types to their corresponding mapping dictionaries
        self.rule_to_mapping = {
            'SQLInjection': self.sql_injection_mappings,
            'SQLInjectionRule': self.sql_injection_mappings,
            'XSS': self.xss_mappings,
            'XSSRule': self.xss_mappings,
            'CommandInjection': self.command_injection_mappings,
            'CommandInjectionRule': self.command_injection_mappings,
            'PathTraversal': self.path_traversal_mappings,
            'PathTraversalRule': self.path_traversal_mappings,
            'BruteForce': self.bruteforce_mappings,
            'BruteForceRule': self.bruteforce_mappings,
            'CSRF': self.csrf_mappings,
            'CSRFRule': self.csrf_mappings,
            'SessionHijacking': self.session_hijacking_mappings,
            'SessionHijackingRule': self.session_hijacking_mappings,
            'RateLimit': self.rate_limit_mappings,
            'RateLimitRule': self.rate_limit_mappings
        }
        
    def map_threat(self, threat_type, threat_data=None, rule=None):
        """
        Map a detected threat to MITRE ATT&CK framework
        
        Args:
            threat_type (str): Type of threat or rule name
            threat_data (dict, optional): Additional threat details
            rule (Rule, optional): The rule object that detected the threat
            
        Returns:
            tuple: (tactic, technique_id, technique_name)
        """
        try:
            # Try to use the rule's class name if available
            if rule and hasattr(rule, '__class__'):
                rule_class_name = rule.__class__.__name__
                
                # Check if we have mappings for this rule type
                if rule_class_name in self.rule_to_mapping:
                    mappings = self.rule_to_mapping[rule_class_name]
                    
                    # Try to determine the specific subtype based on threat data
                    subtype = self._determine_subtype(rule_class_name, threat_data)
                    
                    # Return the mapping for this subtype, or default if not found
                    if subtype in mappings:
                        return mappings[subtype]
                    return mappings['default']
            
            # If rule-based mapping failed, try matching by threat type
            clean_type = threat_type.replace('Rule', '').replace('_', '')
            
            for rule_type, mappings in self.rule_to_mapping.items():
                clean_rule_type = rule_type.replace('Rule', '').replace('_', '')
                
                if clean_type.lower() in clean_rule_type.lower() or clean_rule_type.lower() in clean_type.lower():
                    return mappings['default']
            
            # Special case for SQL Injection detection by pattern
            if threat_data and isinstance(threat_data, dict) and 'description' in threat_data:
                if 'sql' in threat_data['description'].lower() and ('inject' in threat_data['description'].lower() or 
                                                                  'bypass' in threat_data['description'].lower()):
                    return self.sql_injection_mappings['default']
                    
                if 'xss' in threat_data['description'].lower() or 'cross site' in threat_data['description'].lower():
                    return self.xss_mappings['default']
                    
                if 'command' in threat_data['description'].lower() and 'inject' in threat_data['description'].lower():
                    return self.command_injection_mappings['default']
                    
                if 'brute' in threat_data['description'].lower() or 'force' in threat_data['description'].lower():
                    return self.bruteforce_mappings['default']
                    
                if 'csrf' in threat_data['description'].lower() or 'cross site request' in threat_data['description'].lower():
                    return self.csrf_mappings['default']
                
                if 'path' in threat_data['description'].lower() and 'traversal' in threat_data['description'].lower():
                    return self.path_traversal_mappings['default']
                    
                if 'session' in threat_data['description'].lower() and ('hijack' in threat_data['description'].lower() or 
                                                                      'cookie' in threat_data['description'].lower()):
                    return self.session_hijacking_mappings['default']
            
            # Default mapping for unknown threats
            return ('unknown', 'T1000', 'Generic Attack')
            
        except Exception as e:
            logger.error(f"Error mapping threat to MITRE ATT&CK: {e}", exc_info=True)
            return ('unknown', 'T1000', 'Generic Attack')
    
    def _determine_subtype(self, rule_class_name, threat_data):
        """Determine the specific subtype of attack based on threat details"""
        if not threat_data or not isinstance(threat_data, dict):
            return 'default'
            
        # Check for SQL Injection subtypes
        if rule_class_name in ['SQLInjection', 'SQLInjectionRule']:
            description = threat_data.get('description', '').lower()
            patterns = threat_data.get('patterns', [])
            
            if isinstance(patterns, list):
                patterns_text = ' '.join(patterns).lower()
                
                if 'union select' in patterns_text or 'union select' in description:
                    return 'data_extraction'
                elif 'or 1=1' in patterns_text or 'bypass' in description:
                    return 'authentication_bypass'
            
        # Check for XSS subtypes
        elif rule_class_name in ['XSS', 'XSSRule']:
            description = threat_data.get('description', '').lower()
            
            if 'stored' in description or 'persistent' in description:
                return 'stored'
            elif 'dom' in description:
                return 'dom'
                
        # Check for Command Injection subtypes
        elif rule_class_name in ['CommandInjection', 'CommandInjectionRule']:
            description = threat_data.get('description', '').lower()
            
            if 'web shell' in description or 'webshell' in description:
                return 'web_shell'
            elif 'reverse shell' in description or 'reverse connection' in description:
                return 'reverse_shell'
                
        # Check for Path Traversal subtypes
        elif rule_class_name in ['PathTraversal', 'PathTraversalRule']:
            description = threat_data.get('description', '').lower()
            
            if 'passwd' in description or 'shadow' in description or 'credential' in description:
                return 'sensitive_files'
                
        # Check for Brute Force subtypes
        elif rule_class_name in ['BruteForce', 'BruteForceRule']:
            description = threat_data.get('description', '').lower()
            
            if 'password spray' in description:
                return 'password_spraying'
            elif 'credential stuff' in description:
                return 'credential_stuffing'
        
        # Check for CSRF subtypes
        elif rule_class_name in ['CSRF', 'CSRFRule']:
            description = threat_data.get('description', '').lower()
            
            # Check for phpMyAdmin specific routes
            if '/phpmyadmin/' in description or 'index.php?route=' in description:
                if 'admin' in description:
                    return 'admin'
                elif 'config' in description or 'settings' in description:
                    return 'config'
                elif 'import' in description:
                    return 'import'
                elif 'sql' in description or 'query' in description:
                    return 'sql'
                elif 'export' in description:
                    return 'export'
                elif 'server' in description or 'status' in description:
                    return 'server'
                elif 'database' in description or 'db' in description:
                    return 'database'
            
            # Fallback to existing logic for non-phpMyAdmin CSRF
            if 'admin' in description or 'administrator' in description:
                return 'admin'
            elif 'config' in description or 'settings' in description:
                return 'config'
            
            return 'default'
                
        return 'default'

# Singleton instance for global use
mitre_mapper = MitreAttackMapper()