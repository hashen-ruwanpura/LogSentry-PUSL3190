// Self-executing anonymous function to avoid polluting global scope
(function() {
    // Debug flag - set to true for console logs, false for production
    const DEBUG = true;
    
    // Log helper function
    function log(message) {
        if (DEBUG) console.log(`[Notifications] ${message}`);
    }
    
    log("Script loading started");
    
    // Notification system class
    class NotificationSystem {
        constructor(options = {}) {
            log("Initializing notification system");
            this.websocket = null;
            this.reconnectAttempts = 0;
            this.maxReconnectAttempts = 5;
            this.reconnectDelay = 2000; // Start with 2 seconds
            this.notifications = [];
            this.unreadCount = 0;
            this.notificationPermissionRequested = false;
            
            // Configuration options
            this.config = {
                createCounters: options.createCounters !== false,
                createDropdown: options.createDropdown !== false,
                parentElement: options.parentElement || document.body,
                dropdownParent: options.dropdownParent || this.findHeaderElement() || document.body
            };

            try {
                // Initialize UI elements and containers
                this.initializeUI();
                
                // Try to connect WebSocket
                setTimeout(() => this.connect(), 500);
                
                // Request notification permission
                this.requestNotificationPermission();
                
                // Set up ping interval to keep connection alive
                this.pingInterval = setInterval(() => this.ping(), 30000);
                
                // Load initial notifications
                setTimeout(() => this.loadNotifications(), 1000);
                
                log("Notification system initialized successfully");
            } catch (error) {
                console.error("Error initializing notification system:", error);
            }
        }
        
        initializeUI() {
            // Create notification container for popups
            this.createNotificationContainer();
            
            // Create counters if configured
            if (this.config.createCounters) {
                this.createCounters();
            } else {
                // Try to find existing counters
                this.findCounters();
            }
            
            // Create or find notification dropdown
            if (this.config.createDropdown) {
                this.createNotificationDropdown();
            } else {
                this.notificationDropdown = document.getElementById('notification-dropdown');
            }
            
            // Create or find notification badge
            this.notificationBadge = document.getElementById('notification-badge');
            if (!this.notificationBadge && this.notificationDropdown) {
                this.createNotificationBadge();
            }
            
            // Add stylesheet for notifications
            this.addNotificationStyles();
            
            // Enhance any static alerts on the page
            this.enhanceStaticAlerts();
            
            // Specifically enhance system security alerts
            this.enhanceSystemAlerts();
            
            // Also handle alerts that might be added to the page later
            setTimeout(() => {
                this.enhanceStaticAlerts();
                this.enhanceSystemAlerts();
            }, 1000);
            
            setTimeout(() => {
                this.enhanceStaticAlerts();
                this.enhanceSystemAlerts();
            }, 3000);
        }
        
        findHeaderElement() {
            // Try to find a header element to attach the dropdown to
            return document.querySelector('header') || 
                   document.querySelector('.navbar') ||
                   document.querySelector('.header') ||
                   document.querySelector('.main-header');
        }
        
        createCounters() {
            try {
                // Create counter container
                const counterContainer = document.createElement('div');
                counterContainer.id = 'notification-counters';
                counterContainer.className = 'notification-counters';
                counterContainer.style.cssText = 'display: none;'; // Hidden by default
                
                // Create individual counters
                this.counters = {
                    critical: this.createCounter('critical-alert-count', 'Critical Alerts', 'danger'),
                    high: this.createCounter('high-alert-count', 'High Alerts', 'warning'),
                    medium: this.createCounter('medium-alert-count', 'Medium Alerts', 'info'),
                    low: this.createCounter('low-alert-count', 'Low Alerts', 'primary'),
                    total: this.createCounter('total-alert-count', 'Total Alerts', 'secondary')
                };
                
                // Add counters to container
                Object.values(this.counters).forEach(counter => {
                    counterContainer.appendChild(counter);
                });
                
                // Add to document
                this.config.parentElement.appendChild(counterContainer);
            } catch (error) {
                console.error("Error creating counters:", error);
                // Create empty object as fallback
                this.counters = {};
            }
        }
        
        createCounter(id, label, colorClass) {
            const counter = document.createElement('span');
            counter.id = id;
            counter.className = `badge bg-${colorClass}`;
            counter.title = label;
            counter.textContent = '0';
            return counter;
        }
        
        findCounters() {
            try {
                this.counters = {
                    critical: document.getElementById('critical-alert-count'),
                    high: document.getElementById('high-alert-count'),
                    medium: document.getElementById('medium-alert-count'),
                    low: document.getElementById('low-alert-count'),
                    total: document.getElementById('total-alert-count')
                };
                
                // Filter out any null values
                this.counters = Object.fromEntries(
                    Object.entries(this.counters).filter(([_, val]) => val !== null)
                );
            } catch (error) {
                console.error("Error finding counters:", error);
                this.counters = {};
            }
        }
        
        createNotificationDropdown() {
            try {
                // Create dropdown container
                const dropdownContainer = document.createElement('div');
                dropdownContainer.className = 'notification-dropdown-container';
                dropdownContainer.style.cssText = `
                    position: relative;
                    display: inline-block;
                    margin-left: 15px;
                `;
                
                // Create dropdown toggle button
                const toggleButton = document.createElement('button');
                toggleButton.className = 'notification-toggle-btn';
                toggleButton.innerHTML = '<i class="fas fa-bell"></i>';
                toggleButton.style.cssText = `
                    background: none;
                    border: none;
                    color: #333;
                    font-size: 16px;
                    cursor: pointer;
                    position: relative;
                    padding: 5px;
                `;
                
                // Create badge
                this.notificationBadge = document.createElement('span');
                this.notificationBadge.id = 'notification-badge';
                this.notificationBadge.className = 'notification-badge';
                this.notificationBadge.style.cssText = `
                    position: absolute;
                    top: -5px;
                    right: -5px;
                    background-color: #dc3545;
                    color: white;
                    font-size: 10px;
                    font-weight: bold;
                    border-radius: 50%;
                    width: 18px;
                    height: 18px;
                    display: none;
                    align-items: center;
                    justify-content: center;
                `;
                toggleButton.appendChild(this.notificationBadge);
                
                // Create dropdown content
                this.notificationDropdown = document.createElement('div');
                this.notificationDropdown.id = 'notification-dropdown';
                this.notificationDropdown.className = 'notification-dropdown';
                this.notificationDropdown.style.cssText = `
                    position: absolute;
                    right: 0;
                    background-color: white;
                    min-width: 300px;
                    max-width: 400px;
                    box-shadow: 0 8px 16px rgba(0,0,0,0.2);
                    z-index: 1000;
                    border-radius: 4px;
                    overflow: hidden;
                    display: none;
                    max-height: 500px;
                    overflow-y: auto;
                `;
                
                // Add empty notification message
                const emptyMessage = document.createElement('div');
                emptyMessage.className = 'dropdown-item text-center text-muted';
                emptyMessage.innerText = 'No notifications';
                this.notificationDropdown.appendChild(emptyMessage);
                
                // Add click event to toggle
                toggleButton.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const isDisplayed = this.notificationDropdown.style.display === 'block';
                    this.notificationDropdown.style.display = isDisplayed ? 'none' : 'block';
                });
                
                // Close dropdown when clicking outside
                document.addEventListener('click', () => {
                    if (this.notificationDropdown) {
                        this.notificationDropdown.style.display = 'none';
                    }
                });
                
                // Add elements to container
                dropdownContainer.appendChild(toggleButton);
                dropdownContainer.appendChild(this.notificationDropdown);
                
                // Add to document
                this.config.dropdownParent.appendChild(dropdownContainer);
            } catch (error) {
                console.error("Error creating notification dropdown:", error);
            }
        }
        
        createNotificationBadge() {
            try {
                this.notificationBadge = document.createElement('span');
                this.notificationBadge.id = 'notification-badge';
                this.notificationBadge.className = 'notification-badge';
                this.notificationBadge.style.cssText = `
                    background-color: #dc3545;
                    color: white;
                    font-size: 10px;
                    font-weight: bold;
                    border-radius: 50%;
                    width: 18px;
                    height: 18px;
                    display: none;
                    align-items: center;
                    justify-content: center;
                    position: absolute;
                    top: 0;
                    right: 0;
                `;
                
                const bellIcon = document.querySelector('.fa-bell');
                if (bellIcon && bellIcon.parentNode) {
                    bellIcon.parentNode.style.position = 'relative';
                    bellIcon.parentNode.appendChild(this.notificationBadge);
                }
            } catch (error) {
                console.error("Error creating notification badge:", error);
            }
        }
        
        createNotificationContainer() {
            try {
                // Create container for interactive notifications if it doesn't exist
                this.notificationContainer = document.getElementById('notification-container');
                if (!this.notificationContainer) {
                    this.notificationContainer = document.createElement('div');
                    this.notificationContainer.id = 'notification-container';
                    this.notificationContainer.style.cssText = `
                        position: fixed;
                        top: 20px;
                        right: 20px;
                        z-index: 9999;
                        width: 350px;
                        max-height: calc(100vh - 40px);
                        overflow-y: auto;
                        display: flex;
                        flex-direction: column;
                        gap: 10px;
                    `;
                    document.body.appendChild(this.notificationContainer);
                }
            } catch (error) {
                console.error("Error creating notification container:", error);
            }
        }
        
        addNotificationStyles() {
            try {
                if (!document.getElementById('notification-styles')) {
                    const style = document.createElement('style');
                    style.id = 'notification-styles';
                    style.textContent = `
                        .alert-popup {
                            padding: 15px;
                            border-radius: 8px;
                            box-shadow: 0 3px 10px rgba(0,0,0,0.2);
                            animation: slideIn 0.5s ease-out;
                            position: relative;
                            overflow: hidden;
                            background-color: white;
                            transition: all 0.3s ease;
                        }
                        
                        .alert-popup:hover {
                            transform: translateY(-3px);
                            box-shadow: 0 5px 15px rgba(0,0,0,0.25);
                        }
                        
                        .clickable-notification {
                            transition: all 0.2s ease;
                        }
                        
                        .clickable-notification:hover {
                            opacity: 0.95;
                            transform: translateY(-3px);
                        }
                        
                        .alert-popup h4 {
                            margin-top: 0;
                            margin-bottom: 10px;
                            font-size: 16px;
                            font-weight: 600;
                            display: flex;
                            align-items: center;
                            gap: 8px;
                        }
                        
                        .alert-popup p {
                            margin-bottom: 10px;
                            font-size: 14px;
                            word-break: break-word;
                        }
                        
                        .alert-popup .close-btn {
                            position: absolute;
                            top: 5px;
                            right: 5px;
                            background: transparent;
                            border: none;
                            cursor: pointer;
                            font-size: 14px;
                            color: rgba(0,0,0,0.5);
                            padding: 0;
                            width: 18px;
                            height: 18px;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            border-radius: 50%;
                            z-index: 10;
                        }
                        
                        .alert-popup .close-btn:hover {
                            background: rgba(0,0,0,0.05);
                        }
                        
                        .alert-popup .alert-actions {
                            display: flex;
                            gap: 8px;
                            margin-top: 10px;
                        }
                        
                        .alert-popup .alert-action {
                            display: inline-block;
                            padding: 5px 10px;
                            background-color: rgba(0,0,0,0.05);
                            border-radius: 4px;
                            text-decoration: none;
                            font-size: 13px;
                            font-weight: 500;
                            color: inherit;
                            transition: all 0.2s;
                        }
                        
                        .alert-popup .alert-action:hover {
                            background-color: rgba(0,0,0,0.1);
                        }
                        
                        .alert-popup .countdown-bar {
                            position: absolute;
                            bottom: 0;
                            left: 0;
                            height: 3px;
                            background-color: rgba(0,0,0,0.2);
                            width: 100%;
                        }
                        
                        .alert-popup-critical {
                            border-left: 5px solid #dc3545;
                        }
                        
                        .alert-popup-critical h4 {
                            color: #dc3545;
                        }
                        
                        .alert-popup-critical .countdown-bar {
                            background-color: #dc3545;
                        }
                        
                        .alert-popup-high {
                            border-left: 5px solid #fd7e14;
                        }
                        
                        .alert-popup-high h4 {
                            color: #fd7e14;
                        }
                        
                        .alert-popup-high .countdown-bar {
                            background-color: #fd7e14;
                        }
                        
                        .alert-popup-medium {
                            border-left: 5px solid #ffc107;
                        }
                        
                        .alert-popup-medium h4 {
                            color: #ffc107;
                        }
                        
                        .alert-popup-medium .countdown-bar {
                            background-color: #ffc107;
                        }
                        
                        .alert-popup-low {
                            border-left: 5px solid #17a2b8;
                        }
                        
                        .alert-popup-low h4 {
                            color: #17a2b8;
                        }
                        
                        .alert-popup-low .countdown-bar {
                            background-color: #17a2b8;
                        }
                        
                        .notification-dropdown .dropdown-item {
                            padding: 10px 15px;
                            border-bottom: 1px solid #eee;
                            text-decoration: none;
                            color: #333;
                        }
                        
                        .notification-dropdown .dropdown-item:hover {
                            background-color: #f8f9fa;
                        }
                        
                        .notification-dropdown .notification-content {
                            display: flex;
                            align-items: center;
                            gap: 10px;
                        }
                        
                        .notification-dropdown .notification-icon {
                            width: 36px;
                            height: 36px;
                            border-radius: 50%;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            flex-shrink: 0;
                        }
                        
                        .notification-dropdown .notification-details {
                            flex-grow: 1;
                            overflow: hidden;
                        }
                        
                        .notification-dropdown .notification-title {
                            font-weight: 600;
                            margin-bottom: 3px;
                        }
                        
                        .notification-dropdown .notification-message {
                            color: #666;
                            font-size: 13px;
                            white-space: nowrap;
                            overflow: hidden;
                            text-overflow: ellipsis;
                            margin-bottom: 3px;
                        }
                        
                        .notification-dropdown .notification-time {
                            color: #999;
                            font-size: 12px;
                        }
                        
                        .bg-danger {
                            background-color: #dc3545;
                            color: white;
                        }
                        
                        .bg-warning {
                            background-color: #fd7e14;
                            color: #212529;
                        }
                        
                        .bg-info {
                            background-color: #17a2b8;
                            color: white;
                        }
                        
                        .bg-primary {
                            background-color: #007bff;
                            color: white;
                        }
                        
                        .bg-secondary {
                            background-color: #6c757d;
                            color: white;
                        }
                        
                        .text-primary {
                            color: #007bff !important;
                        }
                        
                        .text-secondary {
                            color: #6c757d !important;
                        }
                        
                        .text-center {
                            text-align: center !important;
                        }
                        
                        .text-muted {
                            color: #6c757d !important;
                        }
                        
                        .pulse-animation {
                            animation: pulse 1s ease-out;
                        }
                        
                        @keyframes pulse {
                            0% { transform: scale(1); }
                            50% { transform: scale(1.2); }
                            100% { transform: scale(1); }
                        }
                        
                        @keyframes slideIn {
                            from {
                                transform: translateX(100%);
                                opacity: 0;
                            }
                            to {
                                transform: translateX(0);
                                opacity: 1;
                            }
                        }
                        
                        @keyframes countdown {
                            from { width: 100%; }
                            to { width: 0%; }
                        }
                    `;
                    document.head.appendChild(style);
                }
                // In the addNotificationStyles method, add or modify these styles:
                style.textContent += `
                    /* Static alert enhancements */
                    .alert.clickable-notification {
                        cursor: pointer !important;
                        transition: background-color 0.2s ease;
                    }
                    
                    .alert.clickable-notification:hover {
                        opacity: 0.95;
                    }
                    
                    .alert .close {
                        font-size: 14px !important;
                        opacity: 0.7 !important;
                    }
                    
                    /* Make close button smaller in static alerts */
                    .alert .close-btn:hover {
                        background: rgba(0,0,0,0.05);
                    }
                `;
            } catch (error) {
                console.error("Error adding notification styles:", error);
            }
        }

        connect() {
            try {
                log("Attempting to connect to WebSocket");
                
                // Determine WebSocket protocol (ws or wss)
                const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
                const wsUrl = `${protocol}://${window.location.host}/ws/alerts/`;
                
                this.websocket = new WebSocket(wsUrl);
                
                this.websocket.onopen = (event) => {
                    log("WebSocket connection established");
                    this.reconnectAttempts = 0;
                    this.reconnectDelay = 2000;
                };
                
                this.websocket.onmessage = (event) => {
                    try {
                        const data = JSON.parse(event.data);
                        this.handleWebSocketMessage(data);
                    } catch (e) {
                        console.error('Error processing WebSocket message:', e);
                    }
                };
                
                this.websocket.onclose = (event) => {
                    log("WebSocket connection closed");
                    this.attemptReconnect();
                };
                
                this.websocket.onerror = (error) => {
                    console.error('WebSocket error:', error);
                };
            } catch (e) {
                console.error('Error connecting to WebSocket:', e);
            }
        }
        
        attemptReconnect() {
            if (this.reconnectAttempts < this.maxReconnectAttempts) {
                this.reconnectAttempts++;
                
                log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
                
                setTimeout(() => {
                    this.connect();
                }, this.reconnectDelay);
                
                // Exponential backoff (up to 30 seconds)
                this.reconnectDelay = Math.min(this.reconnectDelay * 1.5, 30000);
            } else {
                console.error('Maximum WebSocket reconnection attempts reached');
            }
        }
        
        handleWebSocketMessage(data) {
            log(`Received WebSocket message: ${data.type}`);
            
            if (data.type === 'alert_notification') {
                this.displayNotification(data.alert);
            } else if (data.type === 'alert_updated') {
                this.updateAlertStatus(data.alert_id, data.status);
            } else if (data.type === 'pong') {
                log('Received pong from server');
            } else if (data.type === 'pending_alerts') {
                if (data.alerts && data.alerts.length > 0) {
                    log(`Received ${data.alerts.length} pending alerts`);
                    data.alerts.forEach((alert, index) => {
                        setTimeout(() => {
                            this.displayNotification(alert);
                        }, index * 500);
                    });
                }
            }
        }
        
        ping() {
            if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                try {
                    this.websocket.send(JSON.stringify({command: 'ping'}));
                    log('Ping sent to server');
                } catch (e) {
                    console.error('Error sending ping:', e);
                }
            }
        }
        
        requestNotificationPermission() {
            if (!this.notificationPermissionRequested && 'Notification' in window) {
                this.notificationPermissionRequested = true;
                
                if (Notification.permission !== 'granted' && Notification.permission !== 'denied') {
                    log('Requesting notification permission');
                    
                    Notification.requestPermission().then(permission => {
                        log(`Notification permission: ${permission}`);
                    }).catch(err => {
                        console.error('Error requesting notification permission:', err);
                    });
                } else {
                    log(`Notification permission already set: ${Notification.permission}`);
                }
            }
        }
        
        displayNotification(alert) {
            log(`Displaying notification: ${alert.severity} - ${alert.title}`);
            
            try {
                // Add to our notifications array
                this.notifications.unshift(alert);
                
                // Limit to latest 100 notifications
                if (this.notifications.length > 100) {
                    this.notifications = this.notifications.slice(0, 100);
                }
                
                // Update UI notification counter
                this.unreadCount++;
                this.updateUnreadBadge();
                
                // Add to notification dropdown
                this.addNotificationToDropdown(alert);
                
                // Show browser notification if permitted
                this.showBrowserNotification(alert);
                
                // Show interactive popup notification
                this.showPopupNotification(alert);
                
                // Update counter for specific severity
                this.updateNotificationCounter(alert.severity);
            } catch (error) {
                console.error("Error displaying notification:", error);
            }
        }
        
        showBrowserNotification(alert) {
            if (Notification.permission === 'granted' && document.visibilityState !== 'visible') {
                try {
                    const notification = new Notification(`[${alert.severity.toUpperCase()}] ${alert.title}`, {
                        body: alert.message,
                        tag: `threat-${alert.threat_id || 'alert'}`,
                        requireInteraction: alert.severity === 'critical'
                    });
                    
                    notification.onclick = function() {
                        window.focus();
                        if (alert.threat_id) {
                            window.location.href = `/alert-detail/${alert.threat_id}/`;
                        }
                        notification.close();
                    };
                    
                    if (alert.severity !== 'critical') {
                        setTimeout(() => notification.close(), 10000);
                    }
                } catch (error) {
                    console.error("Error showing browser notification:", error);
                }
            }
        }
        
        showPopupNotification(alert) {
            try {
                if (!this.notificationContainer) {
                    log("No notification container found. Creating one.");
                    this.createNotificationContainer();
                }
                
                // Create notification element
                const notificationId = `popup-${Date.now()}`;
                const popupElement = document.createElement('div');
                popupElement.id = notificationId;
                popupElement.className = `alert-popup alert-popup-${alert.severity}`;
                
                // Make entire popup clickable if there's a threat_id
                if (alert.threat_id) {
                    popupElement.style.cursor = 'pointer';
                    popupElement.classList.add('clickable-notification');
                }
                
                // Get icon based on severity
                const severityIcon = this.getSeverityIcon(alert.severity);
                
                popupElement.innerHTML = `
                    <h4>${severityIcon} ${alert.title}</h4>
                    <p>${alert.message}</p>
                    <div class="alert-actions">
                        ${alert.threat_id ? 
                          `<a href="/alert-detail/${alert.threat_id}/" class="alert-action">View Details</a>` : 
                          ''}
                        <button class="alert-action mark-read-btn" data-id="${alert.id || ''}">Mark as Read</button>
                    </div>
                    <button class="close-btn">&times;</button>
                    ${alert.severity !== 'critical' ? 
                      `<div class="countdown-bar"></div>` : 
                      ''}
                `;
                
                this.notificationContainer.prepend(popupElement);
                
                // Add countdown animation for non-critical alerts
                if (alert.severity !== 'critical') {
                    const countdownBar = popupElement.querySelector('.countdown-bar');
                    if (countdownBar) {
                        const duration = this.getAutoCloseTime(alert.severity) / 1000;
                        countdownBar.style.animation = `countdown ${duration}s linear forwards`;
                    }
                }
                
                // Make whole notification clickable
                if (alert.threat_id) {
                    popupElement.addEventListener('click', (e) => {
                        // Don't trigger if clicking on close button or mark read button
                        if (!e.target.closest('.close-btn') && !e.target.closest('.mark-read-btn')) {
                            window.location.href = `/alert-detail/${alert.threat_id}/`;
                        }
                    });
                }
                
                // Add event listeners
                const closeBtn = popupElement.querySelector('.close-btn');
                if (closeBtn) {
                    closeBtn.addEventListener('click', (e) => {
                        e.stopPropagation(); // Prevent triggering the parent click event
                        this.removePopupNotification(popupElement);
                    });
                }
                
                const markReadBtn = popupElement.querySelector('.mark-read-btn');
                if (markReadBtn) {
                    markReadBtn.addEventListener('click', (e) => {
                        e.stopPropagation(); // Prevent triggering the parent click event
                        const alertId = markReadBtn.getAttribute('data-id');
                        if (alertId) {
                            this.markNotificationRead(alertId);
                        }
                        this.removePopupNotification(popupElement);
                    });
                }
                
                // Set auto-close timeout for non-critical alerts
                if (alert.severity !== 'critical') {
                    setTimeout(() => {
                        // Check if notification still exists before removing
                        if (document.getElementById(notificationId)) {
                            this.removePopupNotification(popupElement);
                        }
                    }, this.getAutoCloseTime(alert.severity));
                }
            } catch (error) {
                console.error("Error showing popup notification:", error);
            }
        }
        
        removePopupNotification(element) {
            try {
                // Fade out animation
                element.style.opacity = '0';
                element.style.transform = 'translateX(100%)';
                
                // Remove from DOM after animation completes
                setTimeout(() => {
                    if (element.parentNode) {
                        element.parentNode.removeChild(element);
                    }
                }, 300);
            } catch (error) {
                console.error("Error removing popup notification:", error);
                // Fallback direct removal
                if (element.parentNode) {
                    element.parentNode.removeChild(element);
                }
            }
        }
        
        getAutoCloseTime(severity) {
            // Return auto-close time in milliseconds based on severity
            switch (severity) {
                case 'high':
                    return 20000; // 20 seconds
                case 'medium':
                    return 15000; // 15 seconds
                case 'low':
                    return 10000; // 10 seconds
                default:
                    return 15000; // 15 seconds default
            }
        }
        
        addNotificationToDropdown(alert) {
            try {
                if (!this.notificationDropdown) return;
                
                // Clear "no notifications" message if this is the first one
                if (this.notificationDropdown.querySelector('.text-muted')) {
                    this.notificationDropdown.innerHTML = '';
                }
                
                const alertElement = document.createElement('a');
                alertElement.className = `dropdown-item notification-item ${alert.severity}`;
                alertElement.href = alert.threat_id ? `/alert-detail/${alert.threat_id}/` : '/events/';
                if (alert.id) {
                    alertElement.setAttribute('data-id', alert.id);
                }
                
                const severityIcon = this.getSeverityIcon(alert.severity);
                
                alertElement.innerHTML = `
                    <div class="notification-content">
                        <div class="notification-icon ${this.getSeverityClass(alert.severity)}">
                            ${severityIcon}
                        </div>
                        <div class="notification-details">
                            <div class="notification-title">${alert.title}</div>
                            <div class="notification-message">${this.truncateText(alert.message, 60)}</div>
                            <div class="notification-time">${this.getTimeAgo(alert.timestamp)}</div>
                        </div>
                    </div>
                `;
                
                // Enhanced hover effect for better user feedback
                alertElement.style.transition = "background-color 0.2s ease";
                
                // Mark alert as read when clicked
                if (alert.id) {
                    alertElement.addEventListener('click', (e) => {
                        this.markNotificationRead(alert.id);
                    });
                }
                
                // Insert as the first child
                if (this.notificationDropdown.firstChild) {
                    this.notificationDropdown.insertBefore(alertElement, this.notificationDropdown.firstChild);
                } else {
                    this.notificationDropdown.appendChild(alertElement);
                }
                
                // Limit the number of notifications in the dropdown
                const items = this.notificationDropdown.querySelectorAll('.notification-item');
                if (items.length > 10) {
                    // Keep only the 10 most recent
                    const toRemove = Array.from(items).slice(10);
                    toRemove.forEach(item => item.remove());
                }
                
                // If this is not the first notification, add "See All" and "Mark All Read" links
                if (!this.notificationDropdown.querySelector('.see-all-link')) {
                    const seeAllLink = document.createElement('a');
                    seeAllLink.className = 'dropdown-item text-center text-primary see-all-link';
                    seeAllLink.href = '/notifications/';
                    seeAllLink.innerText = 'See All Notifications';
                    this.notificationDropdown.appendChild(seeAllLink);
                    
                    const markAllReadLink = document.createElement('a');
                    markAllReadLink.className = 'dropdown-item text-center text-secondary mark-all-read-link';
                    markAllReadLink.href = '#';
                    markAllReadLink.innerText = 'Mark All As Read';
                    markAllReadLink.addEventListener('click', (e) => {
                        e.preventDefault();
                        this.markAllAsRead();
                    });
                    this.notificationDropdown.appendChild(markAllReadLink);
                }
            } catch (error) {
                console.error("Error adding notification to dropdown:", error);
            }
        }
        
        updateNotificationCounter(severity) {
            try {
                if (!this.counters) return;
                
                // Increment the specific severity counter
                const counter = this.counters[severity];
                if (counter) {
                    const currentCount = parseInt(counter.innerText) || 0;
                    counter.innerText = currentCount + 1;
                    
                    // Add pulse animation to highlight the change
                    counter.classList.add('pulse-animation');
                    setTimeout(() => {
                        counter.classList.remove('pulse-animation');
                    }, 1000);
                }
                
                // Increment the total counter
                if (this.counters.total) {
                    const totalCount = parseInt(this.counters.total.innerText) || 0;
                    this.counters.total.innerText = totalCount + 1;
                    
                    // Add pulse animation to total counter
                    this.counters.total.classList.add('pulse-animation');
                    setTimeout(() => {
                        this.counters.total.classList.remove('pulse-animation');
                    }, 1000);
                }
            } catch (error) {
                console.error("Error updating notification counter:", error);
            }
        }
        
        updateUnreadBadge() {
            try {
                if (this.notificationBadge) {
                    this.notificationBadge.innerText = this.unreadCount;
                    this.notificationBadge.style.display = this.unreadCount > 0 ? 'flex' : 'none';
                    
                    // Add pulse animation to notification badge
                    if (this.unreadCount > 0) {
                        this.notificationBadge.classList.add('pulse-animation');
                        setTimeout(() => {
                            this.notificationBadge.classList.remove('pulse-animation');
                        }, 1000);
                    }
                }
            } catch (error) {
                console.error("Error updating unread badge:", error);
            }
        }
        
        markAllAsRead() {
            try {
                log("Marking all notifications as read");
                this.unreadCount = 0;
                this.updateUnreadBadge();
                
                fetch('/api/notifications/mark-all-read/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': this.getCsrfToken()
                    }
                })
                .then(response => response.json())
                .then(data => {
                    log('All notifications marked as read');
                    
                    // Update UI to reflect all notifications read
                    if (this.notificationDropdown) {
                        document.querySelectorAll('.notification-item').forEach(item => {
                            item.classList.remove('unread');
                        });
                    }
                    
                    // Remove all interactive notifications
                    if (this.notificationContainer) {
                        const popups = this.notificationContainer.querySelectorAll('.alert-popup');
                        popups.forEach(popup => {
                            this.removePopupNotification(popup);
                        });
                    }
                })
                .catch(error => {
                    console.error('Error marking notifications as read:', error);
                });
            } catch (error) {
                console.error("Error in markAllAsRead:", error);
            }
        }
        
        markNotificationRead(notificationId) {
            if (!notificationId) return;
            
            try {
                log(`Marking notification ${notificationId} as read`);
                
                fetch(`/api/notifications/${notificationId}/read/`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': this.getCsrfToken()
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Update the unread count
                        this.unreadCount = Math.max(0, this.unreadCount - 1);
                        this.updateUnreadBadge();
                        
                        // Update UI for this specific notification
                        document.querySelectorAll(`.notification-item[data-id="${notificationId}"]`).forEach(item => {
                            item.classList.remove('unread');
                        });
                        
                        // If WebSocket is open, send message about read status
                        if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                            this.websocket.send(JSON.stringify({
                                command: 'mark_read',
                                alert_id: notificationId
                            }));
                        }
                    }
                })
                .catch(error => {
                    console.error('Error marking notification as read:', error);
                });
            } catch (error) {
                console.error("Error in markNotificationRead:", error);
            }
        }
        
        updateAlertStatus(alertId, status) {
            try {
                log(`Updating alert ${alertId} status to ${status}`);
                
                // Update UI when an alert status changes (e.g., from unread to read)
                if (status === 'read') {
                    document.querySelectorAll(`.notification-item[data-id="${alertId}"]`).forEach(item => {
                        item.classList.remove('unread');
                    });
                    
                    // Update the unread count
                    this.unreadCount = Math.max(0, this.unreadCount - 1);
                    this.updateUnreadBadge();
                }
            } catch (error) {
                console.error("Error updating alert status:", error);
            }
        }
        
        loadNotifications() {
            try {
                log("Loading initial notifications");
                
                fetch('/api/notifications/')
                    .then(response => {
                        if (!response.ok) {
                            throw new Error(`HTTP error ${response.status}`);
                        }
                        return response.json();
                    })
                    .then(data => {
                        this.notifications = data.notifications || [];
                        this.unreadCount = data.unread_count || 0;
                        
                        log(`Loaded ${this.notifications.length} notifications, ${this.unreadCount} unread`);
                        
                        // Update UI
                        this.updateUnreadBadge();
                        
                        // Clear and refill dropdown
                        if (this.notificationDropdown) {
                            this.notificationDropdown.innerHTML = '';
                            
                            // Display latest 10 notifications
                            const recentNotifications = this.notifications.slice(0, 10);
                            
                            if (recentNotifications.length > 0) {
                                recentNotifications.forEach(alert => {
                                    this.addNotificationToDropdown(alert);
                                });
                                
                                // Add "See All" link
                                const seeAllLink = document.createElement('a');
                                seeAllLink.className = 'dropdown-item text-center text-primary';
                                seeAllLink.href = '/notifications/';
                                seeAllLink.innerText = 'See All Notifications';
                                this.notificationDropdown.appendChild(seeAllLink);
                                
                                // Add "Mark All Read" link
                                const markAllReadLink = document.createElement('a');
                                markAllReadLink.className = 'dropdown-item text-center text-secondary';
                                markAllReadLink.href = '#';
                                markAllReadLink.innerText = 'Mark All As Read';
                                markAllReadLink.addEventListener('click', (e) => {
                                    e.preventDefault();
                                    this.markAllAsRead();
                                });
                                this.notificationDropdown.appendChild(markAllReadLink);
                            } else {
                                // No notifications message
                                const emptyMessage = document.createElement('div');
                                emptyMessage.className = 'dropdown-item text-center text-muted';
                                emptyMessage.innerText = 'No notifications';
                                this.notificationDropdown.appendChild(emptyMessage);
                            }
                        }
                    })
                    .catch(error => {
                        console.error('Error loading notifications:', error);
                        if (this.notificationDropdown) {
                            // Set empty state
                            this.notificationDropdown.innerHTML = '';
                            const errorMessage = document.createElement('div');
                            errorMessage.className = 'dropdown-item text-center text-danger';
                            errorMessage.innerText = 'Error loading notifications';
                            this.notificationDropdown.appendChild(errorMessage);
                        }
                    });
            } catch (error) {
                console.error("Error in loadNotifications:", error);
            }
        }
        
        // Helper functions
        getSeverityIcon(severity) {
            switch (severity) {
                case 'critical':
                    return '<i class="fas fa-skull-crossbones"></i>';
                case 'high':
                    return '<i class="fas fa-exclamation-circle"></i>';
                case 'medium':
                    return '<i class="fas fa-exclamation-triangle"></i>';
                case 'low':
                    return '<i class="fas fa-info-circle"></i>';
                default:
                    return '<i class="fas fa-bell"></i>';
            }
        }
        
        getSeverityClass(severity) {
            switch (severity) {
                case 'critical':
                    return 'bg-danger text-white';
                case 'high':
                    return 'bg-warning text-dark';
                case 'medium':
                    return 'bg-info text-dark';
                case 'low':
                    return 'bg-primary text-white';
                default:
                    return 'bg-secondary text-white';
            }
        }
        
        getTimeAgo(timestamp) {
            try {
                const date = new Date(timestamp);
                const now = new Date();
                const seconds = Math.floor((now - date) / 1000);
                
                if (isNaN(date.getTime())) {
                    return 'Unknown time';
                }
                
                if (seconds < 60) {
                    return 'Just now';
                } else if (seconds < 3600) {
                    const minutes = Math.floor(seconds / 60);
                    return `${minutes}m ago`;
                } else if (seconds < 86400) {
                    const hours = Math.floor(seconds / 3600);
                    return `${hours}h ago`;
                } else {
                    const days = Math.floor(seconds / 86400);
                    return `${days}d ago`;
                }
            } catch (error) {
                console.error("Error in getTimeAgo:", error);
                return 'Unknown time';
            }
        }
        
        truncateText(text, maxLength) {
            if (!text) return '';
            if (text.length <= maxLength) return text;
            return text.substring(0, maxLength) + '...';
        }
        
        getCsrfToken() {
            try {
                // First try to get token from form
                const tokenElement = document.querySelector('[name=csrfmiddlewaretoken]');
                if (tokenElement) return tokenElement.value;
                
                // Fallback: try to get from cookie
                const cookieValue = document.cookie
                    .split('; ')
                    .find(row => row.startsWith('csrftoken='))
                    ?.split('=')[1];
                    
                return cookieValue || '';
            } catch (error) {
                console.error("Error getting CSRF token:", error);
                return '';
            }
        }
        
        // Used for manual testing
        testNotification(severity = 'medium') {
            try {
                log(`Testing ${severity} notification`);
                
                this.displayNotification({
                    id: 'test-' + Date.now(),
                    title: 'Test Notification',
                    message: `This is a test ${severity} notification to verify the notification system is working.`,
                    severity: severity,
                    timestamp: new Date().toISOString()
                });
                
                return true;
            } catch (error) {
                console.error("Error in testNotification:", error);
                return false;
            }
        }
        
        enhanceStaticAlerts() {
            try {
                // Find all static alerts in the page (like the yellow banner)
                const staticAlerts = document.querySelectorAll('.alert:not(.alert-popup)');
                
                staticAlerts.forEach(alert => {
                    // Skip if already enhanced
                    if (alert.dataset.enhanced) return;
                    
                    // Mark as enhanced to avoid duplicate processing
                    alert.dataset.enhanced = 'true';
                    
                    // Make alert clickable if it mentions threats or security
                    const alertText = alert.textContent.toLowerCase();
                    if (alertText.includes('threat') || alertText.includes('security')) {
                        // Make the alert clickable (except for the close button)
                        alert.style.cursor = 'pointer !important';
                        alert.classList.add('clickable-notification');
                        
                        // Force position relative for proper close button positioning
                        alert.style.position = 'relative !important';
                        
                        // Add click handler
                        alert.addEventListener('click', (e) => {
                            // Don't follow link if click was on the close button
                            if (!e.target.closest('.close-btn') && !e.target.classList.contains('close')) {
                                window.location.href = '/events/?severity=all&status=new';
                            }
                        });
                    }
                    
                    // Find and completely remove the original close button
                    const closeBtn = alert.querySelector('.close, [data-dismiss="alert"]');
                    if (closeBtn) {
                        if (closeBtn.parentNode) {
                            // Create our custom close button
                            const newCloseBtn = document.createElement('button');
                            newCloseBtn.className = 'close-btn';
                            newCloseBtn.innerHTML = '&times;';
                            newCloseBtn.setAttribute('aria-label', 'Close');
                            
                            // Apply strong inline styles that can't be easily overridden
                            Object.assign(newCloseBtn.style, {
                                position: 'absolute',
                                top: '8px',
                                right: '10px',
                                background: 'transparent',
                                border: 'none',
                                cursor: 'pointer',
                                fontSize: '14px',
                                color: 'rgba(0,0,0,0.5)',
                                padding: '0px',
                                width: '18px',
                                height: '18px',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                borderRadius: '50%',
                                zIndex: '10',
                                lineHeight: '1',
                                fontFamily: 'Arial, sans-serif',
                                opacity: '0.7'
                            });
                            
                            // Add event listener
                            newCloseBtn.addEventListener('click', (e) => {
                                e.stopPropagation();
                                alert.style.display = 'none';
                            });
                            
                            // Add hover effect manually
                            newCloseBtn.addEventListener('mouseover', () => {
                                newCloseBtn.style.background = 'rgba(0,0,0,0.05)';
                            });
                            
                            newCloseBtn.addEventListener('mouseout', () => {
                                newCloseBtn.style.background = 'transparent';
                            });
                            
                            // First add our button
                            closeBtn.parentNode.insertBefore(newCloseBtn, closeBtn);
                            
                            // Then remove original button entirely, not just hiding it
                            closeBtn.parentNode.removeChild(closeBtn);
                        }
                    }
                });
                
                // Set up a MutationObserver to catch dynamically added alerts
                if (!this.alertObserver && typeof MutationObserver !== 'undefined') {
                    this.alertObserver = new MutationObserver((mutations) => {
                        let shouldCheck = false;
                        
                        // Check if any mutations might have added new alerts
                        mutations.forEach(mutation => {
                            if (mutation.type === 'childList' && mutation.addedNodes.length) {
                                shouldCheck = true;
                            }
                        });
                        
                        // If we found potential new alerts, run the enhancement again
                        if (shouldCheck) {
                            setTimeout(() => this.enhanceStaticAlerts(), 50);
                        }
                    });
                    
                    // Start observing the document body for changes
                    this.alertObserver.observe(document.body, { 
                        childList: true,
                        subtree: true
                    });
                }
            } catch (error) {
                console.error("Error enhancing static alerts:", error);
            }
        }
    }

    // Add this code before the end of the self-executing anonymous function
    window.enhanceAllAlerts = function() {
        if (window.notificationSystem) {
            window.notificationSystem.enhanceStaticAlerts();
            window.notificationSystem.enhanceSystemAlerts();
        }
    };

    // Add this to ensure alerts are enhanced after the page fully loads
    window.addEventListener('load', function() {
        if (window.notificationSystem) {
            window.notificationSystem.enhanceSystemAlerts();
        } else {
            console.warn("Notification system not initialized on window load");
            // Try to initialize and enhance
            if (typeof initializeSystem === 'function') {
                initializeSystem();
                setTimeout(() => {
                    if (window.notificationSystem) {
                        window.notificationSystem.enhanceSystemAlerts();
                    }
                }, 100);
            }
        }
    });

    // Define global test function first - will work even before system is initialized
    window.testNotification = function(severity = 'medium') {
        log(`Global test notification function called with severity: ${severity}`);
        
        try {
            // If notification system is already initialized, use it
            if (window.notificationSystem) {
                return window.notificationSystem.testNotification(severity);
            }
            
            // If notification system isn't ready, create a temporary one
            log("Creating temporary notification system");
            const tempSystem = new NotificationSystem({
                createCounters: true,
                createDropdown: true
            });
            
            // Display the test notification
            const result = tempSystem.testNotification(severity);
            
            // Store it if global doesn't exist yet
            if (!window.notificationSystem) {
                window.notificationSystem = tempSystem;
            }
            
            return result;
        } catch (error) {
            console.error("Error in global testNotification function:", error);
            
            // Show a simple alert as fallback
            alert(`[TEST ${severity.toUpperCase()} NOTIFICATION] Notification system error: ${error.message}`);
            return false;
        }
    };
    
    // Initialize notification system
    function initializeSystem() {
        if (!window.notificationSystem) {
            log("Initializing notification system from init function");
            
            try {
                window.notificationSystem = new NotificationSystem({
                    createCounters: true,
                    createDropdown: true
                });
                
                log("Notification system initialized successfully");
            } catch (error) {
                console.error("Failed to initialize notification system:", error);
            }
        }
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeSystem);
    } else {
        // DOM already ready, initialize now
        initializeSystem();
    }
    
    // Backup initialization - 2 seconds after page load
    setTimeout(function() {
        if (!window.notificationSystem) {
            log("Delayed initialization of notification system");
            initializeSystem();
        }
    }, 2000);
    
    // Check WebSocket support and connectivity after page loads
    window.addEventListener('load', function() {
        setTimeout(function() {
            if (!window.notificationSystem || 
                !window.notificationSystem.websocket || 
                window.notificationSystem.websocket.readyState !== WebSocket.OPEN) {
                
                console.warn("Notification system not properly connected. Reinitializing...");
                
                if (typeof testNotification === 'function') {
                    // Force init the system
                    testNotification('low');
                }
            }
        }, 3000);
    });
})();
// Fix security notification banners - direct approach
(function() {
    // Direct fix specific to the security alert banner
    function fixAlertBanner() {
        // Target all security-related alerts with broader selector
        const securityAlerts = Array.from(document.querySelectorAll('.alert'))
            .filter(el => {
                const text = el.textContent.toLowerCase();
                return text.includes('threat') || 
                       text.includes('security') || 
                       (text.includes('found') && text.includes('in logs'));
            });
            
        securityAlerts.forEach(alert => {
            // Skip already processed alerts
            if (alert.dataset.enhanced === 'true') return;
            alert.dataset.enhanced = 'true';
            
            // Force styles with !important to override anything else
            alert.setAttribute('style', `
                position: relative !important; 
                cursor: pointer !important;
                padding-right: 35px !important;
            `);
            
            // Completely remove any existing click handlers first
            const newAlert = alert.cloneNode(true);
            if (alert.parentNode) {
                alert.parentNode.replaceChild(newAlert, alert);
                alert = newAlert;
            }
            
            // Add new click handler
            alert.addEventListener('click', function(e) {
                if (!e.target.closest('button') && !e.target.classList.contains('close')) {
                    window.location.href = '/events/?severity=all&status=new';
                }
            });
            
            // Find and replace close button - try multiple selectors
            const closeBtn = alert.querySelector('.close, .btn-close, [data-dismiss="alert"], button');
            if (closeBtn) {
                // Create new button with forced styles
                const newBtn = document.createElement('button');
                newBtn.type = 'button';
                newBtn.innerHTML = '&times;';
                newBtn.className = 'enhanced-close-btn';
                newBtn.setAttribute('style', `
                    position: absolute !important;
                    top: 8px !important;
                    right: 10px !important;
                    background: transparent !important;
                    border: none !important;
                    font-size: 14px !important;
                    font-weight: normal !important;
                    line-height: 1 !important;
                    padding: 0 !important;
                    margin: 0 !important;
                    width: 16px !important;
                    height: 16px !important;
                    text-align: center !important;
                    opacity: 0.7 !important;
                    cursor: pointer !important;
                    z-index: 100 !important;
                    display: flex !important;
                    align-items: center !important;
                    justify-content: center !important;
                `);
                
                // Add click handler with proper event stopping
                newBtn.onclick = function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    alert.style.display = 'none';
                };
                
                // Replace existing button
                closeBtn.parentNode.replaceChild(newBtn, closeBtn);
            } else {
                // If no close button found, add one
                const newBtn = document.createElement('button');
                newBtn.type = 'button';
                newBtn.innerHTML = '&times;';
                newBtn.className = 'enhanced-close-btn';
                newBtn.setAttribute('style', `
                    position: absolute !important;
                    top: 8px !important;
                    right: 10px !important;
                    background: transparent !important;
                    border: none !important;
                    font-size: 14px !important;
                    font-weight: normal !important;
                    line-height: 1 !important;
                    padding: 0 !important;
                    margin: 0 !important;
                    width: 16px !important;
                    height: 16px !important;
                    text-align: center !important;
                    opacity: 0.7 !important;
                    cursor: pointer !important;
                    z-index: 100 !important;
                `);
                
                newBtn.onclick = function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    alert.style.display = 'none';
                };
                
                alert.appendChild(newBtn);
            }
        });
    }

    // Ensure this function runs frequently enough to catch all alerts
    setInterval(fixAlertBanner, 300);
    
    // Run when DOM is ready
    document.addEventListener('DOMContentLoaded', fixAlertBanner);
    
    // Also run when page is fully loaded
    window.addEventListener('load', fixAlertBanner);
    
    // Run once immediately
    fixAlertBanner();
})();