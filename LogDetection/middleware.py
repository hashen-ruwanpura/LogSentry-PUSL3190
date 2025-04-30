import traceback
import logging

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