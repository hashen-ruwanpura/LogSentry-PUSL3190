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
        # Only process HTML responses that don't already have the notification system
        if response.get('Content-Type', '').startswith('text/html'):
            html_content = response.content.decode('utf-8')
            
            # Check if notification container already exists
            if '<div id="notification-container">' not in html_content and '</body>' in html_content:
                notification_code = self._get_notification_code()
                # Insert notification code before closing body tag
                html_content = html_content.replace('</body>', f'{notification_code}</body>')
                response.content = html_content.encode('utf-8')
        
        return response
    
    def _get_notification_code(self):
        """Return the HTML/JS code for the notification system"""
        return '''
        <!-- Notification Container -->
        <div id="notification-container"></div>
        
        <!-- Notification Script -->
        <script src="/static/js/notifications.js"></script>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                try {
                    console.log("Initializing notification system");
                    window.notificationSystem = new NotificationSystem({
                        redirectUrl: '/notifications/',
                        autoGroupSimilar: true,
                        desktopNotifications: false
                    });
                } catch (e) {
                    console.error("Error initializing notification system:", e);
                }
            });
        </script>
        '''