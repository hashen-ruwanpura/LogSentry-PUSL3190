import requests
from django.conf import settings
import logging

# Configure logger
logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """Integration with threat intelligence feeds"""
    
    @staticmethod
    def check_ip_reputation(ip_address):
        """Check reputation of an IP address against threat intelligence feeds"""
        results = {}
        
        # AbuseIPDB integration
        if hasattr(settings, 'ABUSEIPDB_API_KEY'):
            try:
                response = requests.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    params={
                        'ipAddress': ip_address,
                        'maxAgeInDays': 30
                    },
                    headers={
                        'Key': settings.ABUSEIPDB_API_KEY,
                        'Accept': 'application/json'
                    }
                )
                if response.status_code == 200:
                    data = response.json()
                    results['abuseipdb'] = {
                        'score': data['data']['abuseConfidenceScore'],
                        'reports': data['data']['totalReports'],
                        'last_reported': data['data'].get('lastReportedAt')
                    }
            except Exception as e:
                logger.error(f"Error checking AbuseIPDB: {e}")
        
        # VirusTotal integration
        if hasattr(settings, 'VIRUSTOTAL_API_KEY'):
            try:
                response = requests.get(
                    f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}',
                    headers={
                        'x-apikey': settings.VIRUSTOTAL_API_KEY
                    }
                )
                if response.status_code == 200:
                    data = response.json()
                    results['virustotal'] = {
                        'malicious': data['data']['attributes']['last_analysis_stats']['malicious'],
                        'suspicious': data['data']['attributes']['last_analysis_stats']['suspicious'],
                        'reputation': data['data']['attributes'].get('reputation', 0)
                    }
            except Exception as e:
                logger.error(f"Error checking VirusTotal: {e}")
                
        # Add a simplified version for testing without API keys
        if not results:
            logger.info(f"No TI API keys configured, using mock data for {ip_address}")
            # Mock data based on IP patterns
            if ip_address and ip_address.startswith('203.0.113'):  # TEST-NET-3 range
                results['mock'] = {
                    'score': 85,
                    'reports': 12,
                    'last_reported': '2025-04-01T12:00:00Z'
                }
                
        return results
