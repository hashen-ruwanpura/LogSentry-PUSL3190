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
            
            // Reload the page to get fresh data
            setTimeout(() => {
                window.location.reload();
            }, 800);
        });
    }
    
    // Initialize charts based on data from backend
    initChartsWithBackendData();
});

function initChartsWithBackendData() {
    // Alert Evolution Chart - using data from backend
    const alertsChartEl = document.getElementById('alerts-chart');
    if (alertsChartEl) {
        // Get data from template variables injected by Django
        const chartLabels = JSON.parse(document.getElementById('chart-labels-data').textContent);
        const alertsData = JSON.parse(document.getElementById('alerts-data').textContent);
        
        new Chart(alertsChartEl, {
            type: 'line',
            data: {
                labels: chartLabels,
                datasets: [{
                    label: 'Security Alerts',
                    data: alertsData,
                    borderColor: '#3f51b5',
                    backgroundColor: 'rgba(63, 81, 181, 0.1)',
                    tension: 0.3,
                    fill: true
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
    
    // MITRE ATT&CK Tactics Chart - using data from backend
    const mitreChartEl = document.getElementById('mitre-chart');
    if (mitreChartEl) {
        // Get data from template variables injected by Django
        const mitreLabels = JSON.parse(document.getElementById('mitre-labels-data').textContent);
        const mitreData = JSON.parse(document.getElementById('mitre-data').textContent);
        
        new Chart(mitreChartEl, {
            type: 'doughnut',
            data: {
                labels: mitreLabels,
                datasets: [{
                    data: mitreData,
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 206, 86, 0.7)',
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(153, 102, 255, 0.7)',
                        'rgba(255, 159, 64, 0.7)',
                        'rgba(199, 199, 199, 0.7)',
                        'rgba(83, 102, 255, 0.7)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
    }
}

function updateTimeframe(days) {
    window.location.href = `/dashboard/?days=${days}`;
}

function viewAlertDetails(alertId) {
    // Redirect to alert details page or show a modal with details
    window.location.href = `/alerts/details/${alertId}/`;
}