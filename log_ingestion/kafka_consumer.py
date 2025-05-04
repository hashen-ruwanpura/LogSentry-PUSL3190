# Find your KafkaConsumer class and modify the message processing method:

def process_message(self, message):
    try:
        # Create a wrapper for string messages that provides a .content attribute
        class LogWrapper:
            def __init__(self, content):
                self.content = content
                
        # Get the message value
        log_content = message.value
        
        # If it's bytes, decode it
        if isinstance(log_content, bytes):
            log_content = log_content.decode('utf-8', errors='ignore')
            
        # Create the proper object based on type
        if isinstance(log_content, str):
            # Wrap the string with our adapter object
            log_obj = LogWrapper(log_content)
        else:
            # Use as is if it's already an object
            log_obj = log_content
            
        # Now process with the properly formatted object
        self.parser.parse(log_obj)
        
    except Exception as e:
        self.logger.error(f"Error processing Kafka message: {str(e)}", exc_info=True)