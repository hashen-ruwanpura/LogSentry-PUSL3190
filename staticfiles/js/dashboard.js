// dashboard.js
document.addEventListener('DOMContentLoaded', function() {
    // Sidebar toggle functionality
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebar = document.querySelector('.sidebar');
    const content = document.querySelector('.content');
    
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.toggle('collapsed');
            content.classList.toggle('expanded');
        });
    }
    
    // Mobile sidebar toggle
    if (window.innerWidth <= 768) {
        sidebarToggle.addEventListener('click', function() {
            sidebar.classList.toggle('open');
        });
    }
    
    // Refresh button functionality
    const refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            // Add spinning animation to refresh icon
            this.querySelector('i').classList.add('fa-spin');
            
            // Simulate refresh delay
            setTimeout(() => {
                // Reload the page or fetch new data via AJAX
                window.location.reload();
            }, 1000);
        });
    }
    
    // Initialize charts if they exist
    initCharts();
});

function initCharts() {
    // Alerts Chart
    const alertsChartEl = document.getElementById('alerts-chart');
    if (alertsChartEl) {
        new Chart(alertsChartEl, {
            type: 'line',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                datasets: [{
                    label: 'Server1',
                    data: [65, 59, 80, 81, 56, 55],
                    borderColor: '#3f51b5',
                    tension: 0.1,
                    fill: false
                }, {
                    label: 'Server2',
                    data: [28, 48, 40, 19, 86, 27],
                    borderColor: '#f50057',
                    tension: 0.1,
                    fill: false
                }, {
                    label: 'Server3',
                    data: [33, 25, 35, 51, 54, 76],
                    borderColor: '#4caf50',
                    tension: 0.1,
                    fill: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    // MITRE Chart
    const mitreChartEl = document.getElementById('mitre-chart');
    if (mitreChartEl) {
        new Chart(mitreChartEl, {
            type: 'bar',
            data: {
                labels: ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion'],
                datasets: [{
                    label: 'Frequency',
                    data: [12, 19, 8, 5, 2],
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.2)',
                        'rgba(54, 162, 235, 0.2)',
                        'rgba(255, 206, 86, 0.2)',
                        'rgba(75, 192, 192, 0.2)',
                        'rgba(153, 102, 255, 0.2)'
                    ],
                    borderColor: [
                        'rgba(255, 99, 132, 1)',
                        'rgba(54, 162, 235, 1)',
                        'rgba(255, 206, 86, 1)',
                        'rgba(75, 192, 192, 1)',
                        'rgba(153, 102, 255, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
}