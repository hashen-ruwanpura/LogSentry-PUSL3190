# test_watch.py
import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class TestHandler(FileSystemEventHandler):
    def on_modified(self, event):
        print(f"File changed: {event.src_path}")

def main():
    # Test with the apache log
    log_path = os.path.join(os.getcwd(), 'test_logs', 'apache_access.log')
    print(f"Monitoring: {log_path}")
    print(f"Exists: {os.path.exists(log_path)}")
    
    # Make sure the directory exists
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    
    # Create the file if it doesn't exist
    if not os.path.exists(log_path):
        with open(log_path, 'w') as f:
            pass
    
    event_handler = TestHandler()
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(log_path), recursive=False)
    
    try:
        observer.start()
        print("Monitoring started. Press Ctrl+C to stop.")
        
        # Keep the script running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
        print("Monitoring stopped.")

if __name__ == "__main__":
    main()