import traceback
import logging
import re
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

class DebugMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        # Log the full exception with traceback
        logger.error(f"Unhandled exception in request to {request.path}: {str(exception)}")
        logger.error(traceback.format_exc())
        return None

class NotificationMiddleware(MiddlewareMixin):
    """Middleware to inject notification scripts into all HTML responses"""
    
    def process_response(self, request, response):
        """Inject notification code into HTML responses"""
        if not hasattr(response, 'content'):
            return response
            
        if not response.get('Content-Type', '').startswith('text/html'):
            return response
            
        # Skip injection if it's an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return response
            
        content = response.content.decode('utf-8')
        
        # Only inject if body tag exists, notification container doesn't exist, and notification handler isn't loaded
        if '</body>' in content and 'id="notification-container"' not in content:
            notification_code = self._get_notification_code()
            modified_content = content.replace('</body>', f'{notification_code}</body>')
            response.content = modified_content.encode('utf-8')
            
            # Update content length
            if response.has_header('Content-Length'):
                response['Content-Length'] = len(response.content)
                
        return response
    
    def _get_notification_code(self):
        """Get the notification initialization code"""
        return """
        <div id="notification-container"></div>
        <script src="/static/js/notifications.js"></script>
        <script src="/static/js/notification-handler.js"></script>
        """