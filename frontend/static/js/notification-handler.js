/**
 * Global notification handler
 * This file centralizes notification setup across all pages
 */

// Wait for DOM and notification script to be loaded
function initializeNotifications() {
    if (typeof NotificationSystem !== 'undefined') {
        if (!window.notificationSystem) {
            console.log("Initializing notification system globally");
            
            // Create with standard options
            window.notificationSystem = new NotificationSystem({
                containerSelector: '#notification-container',
                autoConnect: true,
                desktopNotifications: true,
                soundEnabled: true
            });
            
            // Fetch recent notifications immediately
            window.notificationSystem.fetchRecentNotifications();
            
            console.log("Notification system initialized successfully");
        }
    } else {
        console.warn("NotificationSystem class not available yet - will retry");
        setTimeout(initializeNotifications, 500);
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Wait a moment to ensure all scripts are loaded
    setTimeout(initializeNotifications, 100);
});

// Also check if document is already loaded (for dynamic imports)
if (document.readyState === 'complete' || document.readyState === 'interactive') {
    setTimeout(initializeNotifications, 100);
}