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
    window.location.href = `/dashboard/?timeframe=${days}`;
}

function viewAlertDetails(alertId) {
    // Redirect to alert details page or show a modal with details
    window.location.href = `/alert-detail/${alertId}/`;
}

// Function to update charts with new data
function updateCharts(chartData) {
    // Update alerts chart
    if (window.alertsChart && chartData.alerts) {
        window.alertsChart.data.labels = chartData.alerts.labels;
        window.alertsChart.data.datasets[0].data = chartData.alerts.data;
        window.alertsChart.update();
    }
    
    // Update MITRE chart
    if (window.mitreChart && chartData.mitre) {
        window.mitreChart.data.labels = chartData.mitre.labels;
        window.mitreChart.data.datasets[0].data = chartData.mitre.data;
        window.mitreChart.update();
    }
}

// Function to refresh dashboard data via AJAX
function refreshDashboardData(timeframe = '1d') {
    // Show loading indicators
    document.querySelectorAll('.loading-spinner').forEach(spinner => {
        spinner.style.display = 'flex';
    });
    
    fetch(`/dashboard-data-api/?timeframe=${timeframe}`)
        .then(response => response.json())
        .then(data => {
            // Update metrics and charts with new data
            updateMetrics(data.metrics);
            updateCharts(data.charts);
            updateAlertsTable(data.alerts);
            
            // Hide loading indicators
            document.querySelectorAll('.loading-spinner').forEach(spinner => {
                spinner.style.display = 'none';
            });
        })
        .catch(error => {
            console.error('Error refreshing dashboard data:', error);
            
            // Hide loading indicators
            document.querySelectorAll('.loading-spinner').forEach(spinner => {
                spinner.style.display = 'none';
            });
            
            // Show error message
            alert('Failed to refresh dashboard data. Please try again.');
        });
}

// Function to update dashboard metrics
function updateMetrics(metrics) {
    if (!metrics) return;
    
    // Update the metrics on the page
    updateMetricValue('total-logs', metrics.total_logs);
    updateMetricValue('high-alerts', metrics.high_level_alerts);
    updateMetricValue('auth-failures', metrics.auth_failures);
    updateMetricValue('auth-success', metrics.auth_success);
    updateMetricValue('apache-total', metrics.apache_count);
    updateMetricValue('apache-4xx', metrics.apache_4xx);
    updateMetricValue('apache-5xx', metrics.apache_5xx);
    updateMetricValue('mysql-total', metrics.mysql_count);
    updateMetricValue('mysql-slow', metrics.mysql_slow);
}

// Helper function to update a metric value
function updateMetricValue(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

// Function to update alerts table
function updateAlertsTable(alerts) {
    if (!alerts || !Array.isArray(alerts)) return;
    
    const tbody = document.querySelector('.alert-table tbody');
    if (!tbody) return;
    
    // Clear existing rows
    tbody.innerHTML = '';
    
    if (alerts.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = `<td colspan="6" class="text-center">No security alerts in the selected time period</td>`;
        tbody.appendChild(row);
        return;
    }
    
    // Add new rows
    alerts.forEach(alert => {
        const row = document.createElement('tr');
        
        let severityClass = '';
        switch (alert.severity) {
            case 'critical':
                severityClass = 'severity-critical';
                break;
            case 'high':
                severityClass = 'severity-high';
                break;
            case 'medium':
                severityClass = 'severity-medium';
                break;
            default:
                severityClass = 'severity-low';
        }
        
        row.innerHTML = `
            <td>${alert.timestamp}</td>
            <td>${alert.source_ip || 'Unknown'}</td>
            <td class="${severityClass}">${alert.severity.charAt(0).toUpperCase() + alert.severity.slice(1)}</td>
            <td>${alert.mitre_tactic || 'Unclassified'}</td>
            <td>${truncateText(alert.description, 70)}</td>
            <td>
                <button onclick="viewAlertDetails(${alert.id})" class="btn btn-sm btn-outline-primary">
                    <i class="fas fa-eye"></i> Details
                </button>
            </td>
        `;
        
        tbody.appendChild(row);
    });
}

// Helper function to truncate text
function truncateText(text, maxLength) {
    if (!text) return '';
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}