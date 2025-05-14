var DEBUG = true;

// Global notification function
window.testNotification = function(severity = 'medium') {
    console.log("Test notification triggered with severity: " + severity);
    
    try {
        // Create alert object
        const testAlert = {
            id: Date.now(),
            title: `Test ${severity.toUpperCase()} Alert`,
            message: `This is a test ${severity} notification`,
            severity: severity,
            timestamp: new Date().toISOString()
        };
        
        // Display browser notification if possible
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(`${severity.toUpperCase()} Alert`, {
                body: `This is a test ${severity} notification`,
                icon: '/static/images/notification-icon.png'
            });
        }
        
        // Show alert message
        alert(`TEST ${severity.toUpperCase()} NOTIFICATION: This is a test notification`);
        
        return testAlert;
    } catch (e) {
        console.error("Error in testNotification:", e);
        return false;
    }
};

// Log helper function
function log(message) {
    if (DEBUG) console.log(`[Notifications] ${message}`);
}

log("Script loading started");

// Simple notification system
window.NotificationSystem = class NotificationSystem {
    constructor(options = {}) {
        log("Initializing notification system");
        this.options = options;
        this.notifications = []; // Track displayed notifications
        this.unreadCount = 0;
        this.lastFetchTime = 0; // Track last fetch time
        
        // Initialize
        this.init();
    }
    
    init() {
        try {
            // Create notification container
            this.createNotificationContainer();
            
            // Request notification permission
            this.requestNotificationPermission();
            
            // Set up polling for notifications
            this.setupPolling();
            
            log("Notification system initialized successfully");
        } catch (error) {
            console.error("Error initializing notification system:", error);
        }
    }
    
    // Update the notification container creation method
    createNotificationContainer() {
        // Create container for notifications if it doesn't exist
        this.container = document.getElementById('notification-container');
        if (!this.container) {
            // Create style element for animations
            const style = document.createElement('style');
            style.id = 'notification-styles';
            style.textContent = `
                @keyframes slideInRight {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
                @keyframes fadeOut {
                    from { opacity: 1; }
                    to { opacity: 0; }
                }
                @keyframes bounceIn {
                    0% { transform: scale(0.8); opacity: 0; }
                    50% { transform: scale(1.05); }
                    70% { transform: scale(0.95); }
                    100% { transform: scale(1); opacity: 1; }
                }
            `;
            document.head.appendChild(style);
            
            // Create container with proper positioning
            this.container = document.createElement('div');
            this.container.id = 'notification-container';
            this.container.style.cssText = `
                position: fixed !important;
                top: 20px !important;
                right: 20px !important;
                z-index: 999999 !important;
                width: 350px !important;
                max-width: 90% !important;
                display: flex !important;
                flex-direction: column !important;
                gap: 10px !important;
                pointer-events: auto !important;
            `;
            document.body.appendChild(this.container);
            log("Notification container created");
        }
    }
    
    requestNotificationPermission() {
        if ('Notification' in window && Notification.permission !== 'granted' && Notification.permission !== 'denied') {
            log('Requesting notification permission');
            Notification.requestPermission();
        } else {
            log(`Notification permission already set: ${Notification.permission}`);
        }
    }
    
    setupPolling() {
        log("Setting up notification polling");
        
        // Poll every 10 seconds
        this.pollingInterval = setInterval(() => {
            this.fetchNotifications();
        }, 10000);
        
        // Initial fetch
        this.fetchNotifications();
    }
    
    // Update the fetchNotifications method to use both API endpoints
    fetchNotifications() {
        log("Fetching notifications from server");
        
        // Use recent notifications API with debug mode
        fetch('/api/notifications/recent/?debug=true', {
            method: 'GET',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'Cache-Control': 'no-cache',
                'pragma': 'no-cache'
            },
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log("Notifications received:", data);
            
            // Store last fetch timestamp
            this.lastFetchTime = Date.now();
            
            if (data.notifications && Array.isArray(data.notifications)) {
                log(`Received ${data.notifications.length} notifications`);
                
                // Process each notification - display NEW ones immediately
                data.notifications.forEach(notification => {
                    // Check if we haven't already displayed this notification
                    if (!this.notifications.some(n => n.id === notification.id)) {
                        this.notifications.push(notification); // Store it
                        this.displayNotification(notification); // Display it visually
                    }
                });
            } else {
                log("No notifications received or invalid format");
            }
        })
        .catch(error => {
            console.error("Error fetching notifications:", error);
        });
    }
    
    // Update the displayNotification method to match the test page style
    displayNotification(alert) {
        log(`Displaying notification: ${alert.severity} - ${alert.title}`);
        
        try {
            // Create notification element with improved styling matching test page
            const notification = document.createElement('div');
            notification.id = `notification-${alert.id || Date.now()}`;
            notification.className = `notification-alert severity-${alert.severity}`;
            notification.style.cssText = `
                margin-bottom: 10px;
                position: relative;
                background-color: white;
                border-radius: 8px;
                padding: 15px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.25);
                animation: bounceIn 0.5s ease-out;
                overflow: hidden;
                cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
                opacity: 1;
                z-index: 999999;
            `;
            
            // Set the appropriate color based on severity
            const severityColor = this.getSeverityColor(alert.severity);
            notification.style.borderLeft = `5px solid ${severityColor}`;
            
            // Create the content structure matching the test notification
            const iconClass = this.getSeverityIcon(alert.severity);
            
            // HTML structure similar to test page
            notification.innerHTML = `
                <div class="close-btn" style="position: absolute; top: 10px; right: 10px; cursor: pointer;">×</div>
                <div style="display: flex; align-items: center;">
                    <div style="
                        background-color: ${severityColor};
                        color: white;
                        width: 28px;
                        height: 28px;
                        border-radius: 50%;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        margin-right: 10px;
                    ">
                        <i class="fas ${iconClass}"></i>
                    </div>
                    <strong>${alert.title}</strong>
                </div>
                <p style="margin: 10px 0 10px 38px;">${alert.message}</p>
                <div style="margin-left: 38px; margin-top: 5px;">
                    <span style="
                        display: inline-block;
                        padding: 2px 8px;
                        border-radius: 4px;
                        font-size: 0.8rem;
                        font-weight: 500;
                        text-transform: uppercase;
                        background-color: ${this.getSeverityColor(alert.severity, true)};
                        color: ${this.getSeverityColor(alert.severity)};
                    ">${alert.severity}</span>
                </div>
            `;
            
            // Add to container
            this.container.appendChild(notification);
            
            // Add click event to redirect to alert detail
            notification.addEventListener('click', (e) => {
                // If clicking the close button, just close the notification
                if (e.target.classList.contains('close-btn')) {
                    this.removeNotification(notification);
                    if (alert.id) this.markAsRead(alert.id);
                    return;
                }
                
                // Otherwise navigate to alert detail page
                if (alert.threat_id) {
                    window.location.href = `/alert/${alert.threat_id}/`;
                } else {
                    window.location.href = '/notifications/'; // Fallback to all notifications
                }
                
                // Mark as read
                if (alert.id) this.markAsRead(alert.id);
            });
            
            // Auto-remove after 10 seconds for non-critical alerts
            if (alert.severity !== 'critical') {
                setTimeout(() => {
                    if (notification.parentNode) {
                        this.removeNotification(notification);
                    }
                }, 10000);
            }
            
            return true;
        } catch (error) {
            console.error("Error displaying notification:", error);
            return false;
        }
    }
    
    // Add method to handle removing notifications with animation
    removeNotification(notification) {
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100%)';
        notification.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
        
        setTimeout(() => {
            if (notification && notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }
    
    // Add this method for the manual test function
    testVisibleNotification(severity = 'medium') {
        const testAlert = {
            id: Date.now(),
            title: `Test ${severity.toUpperCase()} Alert`,
            message: `This is a test ${severity} notification created at ${new Date().toLocaleTimeString()}`,
            severity: severity,
            created_at: new Date().toISOString()
        };
        
        return this.displayNotification(testAlert);
    }
    
    markAsRead(notificationId) {
        log(`Marking notification ${notificationId} as read`);
        
        // Make sure notificationId is a valid database ID, not a timestamp
        if (typeof notificationId === 'number' && notificationId > 0) {
            fetch(`/api/notifications/${notificationId}/read/`, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': this.getCsrfToken(),
                    'Content-Type': 'application/json'
                }
            });
        } else {
            console.error('Invalid notification ID:', notificationId);
        }
    }
    
    // Get CSRF token
    getCsrfToken() {
        // Try to get from meta tag
        const tokenElement = document.querySelector('meta[name="csrf-token"]');
        if (tokenElement) return tokenElement.getAttribute('content');
        
        // Try to get from form
        const formTokenElement = document.querySelector('[name=csrfmiddlewaretoken]');
        if (formTokenElement) return formTokenElement.value;
        
        // Try to get from cookie
        const cookieValue = document.cookie
            .split('; ')
            .find(row => row.startsWith('csrftoken='))
            ?.split('=')[1];
        
        return cookieValue || '';
    }
    
    // Helper function to get severity color
    getSeverityColor(severity, isLight = false) {
        const colors = {
            critical: isLight ? 'rgba(220, 53, 69, 0.1)' : '#dc3545',
            high: isLight ? 'rgba(255, 193, 7, 0.1)' : '#ffc107',
            medium: isLight ? 'rgba(23, 162, 184, 0.1)' : '#17a2b8',
            low: isLight ? 'rgba(40, 167, 69, 0.1)' : '#28a745'
        };
        
        return colors[severity] || colors.medium;
    }

    // Helper function to get severity icon
    getSeverityIcon(severity) {
        const icons = {
            critical: 'fa-skull-crossbones',
            high: 'fa-exclamation-circle',
            medium: 'fa-exclamation-triangle',
            low: 'fa-info-circle'
        };
        
        return icons[severity] || icons.medium;
    }
};

// Add a global test function for easy testing from any page
window.testNotificationSystem = function(severity = 'medium') {
    if (window.notificationSystem) {
        return window.notificationSystem.testVisibleNotification(severity);
    } else {
        console.error("Notification system not initialized");
        alert("TEST NOTIFICATION: Notification system not initialized.");
        return false;
    }
};

// Initialize notification system when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    log("Enhancing system alerts");
    
    // Initialize notification system if not already initialized
    if (typeof window.notificationSystem === 'undefined') {
        window.notificationSystem = new NotificationSystem();
        
        // Register the global test function
        window.testNotification = function(severity = 'medium') {
            return window.notificationSystem.testNotification(severity);
        };
    }
});

// Comment out or modify this function to disable WebSocket connection attempts
function setupWebSocket() {
    console.log("WebSocket connections disabled - using polling instead");
    return null;
    
    // Original WebSocket code below - commented out
    /*
    try {
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws/alerts/`;
        // ...rest of function
    */
}

// Initialize WebSocket when page loads
document.addEventListener('DOMContentLoaded', function() {
    setupWebSocket();
});
