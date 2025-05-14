importScripts('https://www.gstatic.com/firebasejs/8.10.1/firebase-app.js');
importScripts('https://www.gstatic.com/firebasejs/8.10.1/firebase-messaging.js');

// Firebase configuration - same as in your notifications.js
firebase.initializeApp({
    apiKey: "AIzaSyC4LxjvDxUoCTIQCpKWw5COpsy-s_heTDg",
    authDomain: "sylvan-task-457711-r5.firebaseapp.com",
    projectId: "sylvan-task-457711-r5",
    storageBucket: "sylvan-task-457711-r5.firebasestorage.app",
    messagingSenderId: "122346247533",
    appId: "1:122346247533:web:2b42e4b31d1a2d86363664",
    measurementId: "G-3YF6GFH7T5"
});

const messaging = firebase.messaging();

// Handle background messages
messaging.onBackgroundMessage((payload) => {
    console.log('[firebase-messaging-sw.js] Received background message:', payload);
    
    const notificationTitle = payload.notification?.title || 'Security Alert';
    const notificationOptions = {
        body: payload.notification?.body || 'A security threat has been detected.',
        icon: '/static/images/notification-icon.png',
        badge: '/static/images/badge-icon.png',
        data: payload.data || {},
        requireInteraction: payload.data?.severity === 'critical'
    };
    
    return self.registration.showNotification(notificationTitle, notificationOptions);
});

// Handle notification click
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    
    // Navigate to appropriate page when clicked
    const urlToOpen = new URL('/', self.location.origin).href;
    
    event.waitUntil(
        clients.matchAll({type: 'window', includeUncontrolled: true})
            .then((clientList) => {
                for (const client of clientList) {
                    if (client.url === urlToOpen && 'focus' in client) {
                        return client.focus();
                    }
                }
                
                return clients.openWindow(urlToOpen);
            })
    );
});