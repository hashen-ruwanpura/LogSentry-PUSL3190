var DEBUG = true;

// Global notification settings
const NOTIFICATION_EXPIRY_TIME = 10 * 1000; // 10 seconds in milliseconds
// Store permanently viewed notifications (not just temporarily hidden)
const VIEWED_NOTIFICATIONS_KEY = 'viewed_notifications';

// Log helper function
function log(message) {
    if (DEBUG) console.log(`[Notifications] ${message}`);
}

log("Script loading started");

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

// Get viewed notifications from storage - these shouldn't be shown again
function getViewedNotifications() {
    try {
        const stored = localStorage.getItem(VIEWED_NOTIFICATIONS_KEY);
        return stored ? JSON.parse(stored) : {};
    } catch (e) {
        console.error('Error retrieving viewed notifications from localStorage', e);
        return {};
    }
}

// Mark a notification as permanently viewed
function markNotificationViewed(alert) {
    if (!alert || !alert.id) return false;
    
    try {
        // Get currently viewed notifications
        const viewedNotifications = getViewedNotifications();
        
        // Add this notification ID as viewed permanently
        viewedNotifications[alert.id] = new Date().getTime();
        
        // Save back to localStorage
        localStorage.setItem(VIEWED_NOTIFICATIONS_KEY, JSON.stringify(viewedNotifications));
        return true;
    } catch (e) {
        console.error('Error storing viewed notification in localStorage', e);
        return false;
    }
}

// Check if a notification has been viewed already
function isNotificationViewed(alert) {
    if (!alert || !alert.id) return false;
    
    const viewedNotifications = getViewedNotifications();
    return !!viewedNotifications[alert.id];
}

// Temporary notification display tracking (within session)
function shouldDisplayNotification(alert) {
    // If it's a permanent notification that's been viewed, don't show it
    if (alert.id && isNotificationViewed(alert)) {
        log(`Notification ${alert.id} already viewed, skipping`);
        return false;
    }

    // Create a unique ID for this notification
    const notificationId = createNotificationId(alert);
    
    // Check localStorage for displayed notifications
    const displayedNotifications = getDisplayedNotifications();
    
    // If this notification ID exists and hasn't expired, don't display it again
    if (displayedNotifications[notificationId]) {
        const timestamp = displayedNotifications[notificationId];
        const now = new Date().getTime();
        
        // If notification is still within expiry window, don't display
        if (now - timestamp < NOTIFICATION_EXPIRY_TIME) {
            log(`Notification ${notificationId} already displayed recently, skipping`);
            return false;
        }
    }
    
    return true;
}

function storeDisplayedNotification(alert) {
    const notificationId = createNotificationId(alert);
    const displayedNotifications = getDisplayedNotifications();
    
    // Store with current timestamp
    displayedNotifications[notificationId] = new Date().getTime();
    
    // Save back to localStorage
    try {
        localStorage.setItem('displayed_notifications', JSON.stringify(displayedNotifications));
    } catch (e) {
        console.error('Error storing notification in localStorage', e);
    }
}

function getDisplayedNotifications() {
    try {
        const stored = localStorage.getItem('displayed_notifications');
        return stored ? JSON.parse(stored) : {};
    } catch (e) {
        console.error('Error retrieving notifications from localStorage', e);
        return {};
    }
}

function createNotificationId(alert) {
    // Use content to create a reasonably unique ID
    let idSource = `${alert.title || ''}-${alert.severity || ''}-${alert.message?.substring(0, 50) || ''}`;
    
    // If alert has a specific ID, use that as well
    if (alert.id) {
        idSource = `${alert.id}-${idSource}`;
    } else if (alert.threat_id) {
        idSource = `${alert.threat_id}-${idSource}`;
    }
    
    // Simple hash function
    let hash = 0;
    for (let i = 0; i < idSource.length; i++) {
        const char = idSource.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32bit integer
    }
    
    return `notification-${Math.abs(hash)}`;
}

function cleanupExpiredNotifications() {
    const displayedNotifications = getDisplayedNotifications();
    const now = new Date().getTime();
    let changed = false;
    
    // Remove expired notifications
    for (const [id, timestamp] of Object.entries(displayedNotifications)) {
        if (now - timestamp >= NOTIFICATION_EXPIRY_TIME) {
            delete displayedNotifications[id];
            changed = true;
        }
    }
    
    // Save back if changed
    if (changed) {
        try {
            localStorage.setItem('displayed_notifications', JSON.stringify(displayedNotifications));
        } catch (e) {
            console.error('Error updating notifications in localStorage', e);
        }
    }
}

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
            
            // Connect WebSocket
            this.connectWebSocket();
            
            // Set up periodic cleanup of expired notifications
            setInterval(cleanupExpiredNotifications, 30000);
            
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
    
    // Update the fetchNotifications method to filter viewed notifications
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
                    // Skip notifications that have been viewed before
                    if (notification.id && isNotificationViewed(notification)) {
                        log(`Skipping already viewed notification ${notification.id}`);
                        return;
                    }
                    
                    // Skip notifications that are marked as read
                    if (notification.is_read) {
                        log(`Skipping already read notification ${notification.id}`);
                        return;
                    }
                    
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
    
    // Update the displayNotification method to check if we should display
    displayNotification(alert) {
        console.log(`Checking notification: ${alert.severity} - ${alert.title}`);
        
        // Check if we should display this notification (not recently displayed)
        if (!shouldDisplayNotification(alert)) {
            console.log("Notification was recently displayed or already viewed, skipping");
            return false;
        }
        
        // Store this notification as displayed temporarily
        storeDisplayedNotification(alert);
        
        console.log(`Displaying notification: ${alert.severity} - ${alert.title}`);
        
        try {
            // Create notification element with improved styling matching the image
            const notification = document.createElement('div');
            notification.id = `notification-${alert.id || Date.now()}`;
            notification.className = `notification-alert severity-${alert.severity}`;
            notification.style.cssText = `
                margin-bottom: 10px;
                position: relative;
                background-color: white;
                border-radius: 8px;
                padding: 15px 15px 15px 12px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.18);
                animation: bounceIn 0.5s ease-out;
                overflow: hidden;
                cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
                opacity: 1;
                z-index: 999999;
                border-left: 4px solid ${this.getSeverityColor(alert.severity)};
            `;
            
            // Add close button - smaller and better positioned
            const closeBtn = document.createElement('button');
            closeBtn.className = 'close-btn';
            closeBtn.innerHTML = '&times;';
            closeBtn.style.cssText = `
                position: absolute;
                top: 6px;
                right: 10px;
                background: none;
                border: none;
                font-size: 16px;
                cursor: pointer;
                color: #666;
                padding: 0;
                line-height: 1;
                width: 16px;
                height: 16px;
                display: flex;
                align-items: center;
                justify-content: center;
            `;
            
            // Get alert icon based on the image style
            let icon = '<i class="fas fa-info-circle"></i>';
            if (alert.severity === 'high' || alert.severity === 'critical') {
                icon = '<i class="fas fa-exclamation-triangle"></i>';
            }
            
            // Format message to match the image
            let message = alert.message;
            if (message && message.length > 150) {
                message = message.substring(0, 147) + '...';
            }
            
            // Add content - structure similar to image 2
            notification.innerHTML = `
                <div style="display: flex;">
                    <div style="margin-right: 12px; color: ${this.getSeverityColor(alert.severity)}; margin-top: 2px;">
                        ${icon}
                    </div>
                    <div style="flex: 1; min-width: 0;">
                        <strong style="display: block; margin-bottom: 5px; color: #333; font-size: 14px;">${alert.title}</strong>
                        <p style="margin: 0 0 8px 0; color: #555; font-size: 13px; line-height: 1.4;">${message}</p>
                        <div style="display: flex; align-items: center; flex-wrap: wrap; gap: 5px; margin-top: 5px;">
                            <span style="
                                display: inline-block;
                                padding: 3px 8px;
                                border-radius: 4px;
                                font-size: 11px;
                                font-weight: 500;
                                text-transform: uppercase;
                                background-color: ${this.getSeverityColor(alert.severity, true)};
                                color: ${this.getSeverityColor(alert.severity)};
                            ">${alert.severity}</span>
                            
                            ${alert.source_ip ? 
                                `<span style="font-size: 11px; color: #666; display: flex; align-items: center;">
                                    <i class="fas fa-globe" style="margin-right: 3px; font-size: 10px;"></i>
                                    ${alert.source_ip}
                                </span>` : ''}
                        </div>
                    </div>
                </div>
            `;
            
            notification.appendChild(closeBtn);
            
            // Update container styling to match image
            let container = document.getElementById('notification-container');
            if (!container) {
                container = document.createElement('div');
                container.id = 'notification-container';
                container.style.cssText = `
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    width: 360px;
                    max-width: 90%;
                    z-index: 999999;
                    display: flex;
                    flex-direction: column;
                    gap: 10px;
                    pointer-events: none;
                `;
                document.body.appendChild(container);
            }
            
            // Make the notification itself respond to pointer events
            notification.style.pointerEvents = 'auto';
            
            // Add to container
            container.appendChild(notification);
            
            // Hover effect
            notification.addEventListener('mouseenter', () => {
                notification.style.transform = 'translateY(-2px)';
                notification.style.boxShadow = '0 8px 15px rgba(0,0,0,0.2)';
            });
            
            notification.addEventListener('mouseleave', () => {
                notification.style.transform = '';
                notification.style.boxShadow = '0 5px 15px rgba(0,0,0,0.18)';
            });
            
            // Add click events and rest of the function as before
            notification.addEventListener('click', (e) => {
                // If clicking the close button, just close the notification
                if (e.target === closeBtn || e.target.closest('.close-btn')) {
                    this.removeNotification(notification);
                    
                    // Mark as read on server and in localStorage
                    if (alert.id) {
                        this.markAsRead(alert.id);
                        markNotificationViewed(alert);
                    }
                    return;
                }
                
                // Mark as read on server and in localStorage
                if (alert.id) {
                    this.markAsRead(alert.id);
                    markNotificationViewed(alert);
                }
                
                // Otherwise navigate to alert detail page
                if (alert.threat_id) {
                    window.location.href = `/alert-detail/${alert.threat_id}/`;
                } else {
                    window.location.href = '/notifications/';
                }
            });
            
            // Auto-remove after 10 seconds for non-critical alerts
            if (alert.severity !== 'critical') {
                setTimeout(() => {
                    if (notification.parentNode) {
                        this.removeNotification(notification);
                        
                        // Also mark as read when auto-removed
                        if (alert.id) {
                            this.markAsRead(alert.id);
                            markNotificationViewed(alert);
                        }
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
        log(`Marking notification ${notificationId} as read on server`);
        
        // Make sure notificationId is valid
        if (!notificationId) return false;
        
        // Make API call to mark as read on server
        fetch(`/api/notifications/${notificationId}/read/`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': this.getCsrfToken(),
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                log(`Successfully marked notification ${notificationId} as read`);
            } else {
                log(`Error marking notification ${notificationId} as read: ${data.error || 'Unknown error'}`);
            }
        })
        .catch(error => {
            console.error(`Error marking notification ${notificationId} as read:`, error);
        });
        
        return true;
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
    getSeverityColor(severity, isBackground = false) {
        if (isBackground) {
            switch (severity) {
                case 'critical': return 'rgba(220, 53, 69, 0.1)';
                case 'high': return 'rgba(253, 126, 20, 0.1)';
                case 'medium': return 'rgba(255, 193, 7, 0.1)';
                case 'low': return 'rgba(23, 162, 184, 0.1)';
                default: return 'rgba(108, 117, 125, 0.1)';
            }
        } else {
            switch (severity) {
                case 'critical': return '#dc3545';
                case 'high': return '#fd7e14';
                case 'medium': return '#ffc107';
                case 'low': return '#17a2b8';
                default: return '#6c757d';
            }
        }
    }

    // Helper function to get severity icon
    getSeverityIcon(severity) {
        switch (severity) {
            case 'critical': return '<i class="fas fa-skull-crossbones"></i>';
            case 'high': return '<i class="fas fa-exclamation-circle"></i>';
            case 'medium': return '<i class="fas fa-exclamation-triangle"></i>';
            case 'low': return '<i class="fas fa-info-circle"></i>';
            default: return '<i class="fas fa-bell"></i>';
        }
    }

    // Add this method to the NotificationSystem class
    connectWebSocket() {
        try {
            // Close existing connection if any
            if (this.socket && this.socket.readyState !== WebSocket.CLOSED) {
                this.socket.close();
            }
            
            // Determine WebSocket URL (secure or not)
            const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${wsProtocol}//${window.location.host}/ws/alerts/`;
            
            console.log(`Connecting to WebSocket: ${wsUrl}`);
            this.socket = new WebSocket(wsUrl);
            
            // Set up event handlers
            this.socket.onopen = (e) => {
                console.log('WebSocket connection established');
                
                // Send ping to verify connection
                setTimeout(() => {
                    if (this.socket.readyState === WebSocket.OPEN) {
                        this.socket.send(JSON.stringify({
                            command: 'ping',
                            data: { client_id: this.clientId }
                        }));
                    }
                }, 1000);
            };
            
            this.socket.onmessage = (e) => {
                try {
                    const data = JSON.parse(e.data);
                    console.log('WebSocket message received:', data);
                    
                    // Handle different message types
                    if (data.type === 'alert_notification' && data.alert) {
                        // Check if notification has been viewed before
                        if (!data.alert.id || !isNotificationViewed(data.alert)) {
                            this.displayNotification(data.alert);
                        }
                    } else if (data.type === 'notification_alert' && data.notification) {
                        // Check if notification has been viewed before
                        if (!data.notification.id || !isNotificationViewed(data.notification)) {
                            this.displayNotification(data.notification);
                        }
                    } else if (data.type === 'pong') {
                        console.log('WebSocket ping successful');
                    }
                } catch (error) {
                    console.error('Error processing WebSocket message:', error);
                }
            };
            
            this.socket.onclose = (e) => {
                console.log('WebSocket connection closed');
                
                // Attempt to reconnect after delay
                setTimeout(() => this.connectWebSocket(), 5000);
            };
            
            this.socket.onerror = (e) => {
                console.error('WebSocket error:', e);
            };
            
            return true;
        } catch (error) {
            console.error('Error connecting to WebSocket:', error);
            return false;
        }
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
