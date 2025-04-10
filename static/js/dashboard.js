// Dashboard functionality for the Threat Detection & Incident Response system

// Chart objects
let statsChart;
let alertsChart;
let alertsTable;
let refreshInterval;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
    
    // Set up refresh interval (every 30 seconds)
    refreshInterval = setInterval(refreshDashboardData, 30000);
    
    // Set up event listeners
    document.getElementById('refresh-btn').addEventListener('click', refreshDashboardData);
    document.getElementById('timeframe-selector').addEventListener('change', refreshDashboardData);
    
    // Set up incident response actions
    document.getElementById('alerts-table').addEventListener('click', function(e) {
        if (e.target.classList.contains('response-action')) {
            handleResponseAction(e.target.dataset.incidentId, e.target.dataset.action);
        }
    });
});

function initializeDashboard() {
    // Initialize statistics chart
    const statsCtx = document.getElementById('stats-chart').getContext('2d');
    statsChart = new Chart(statsCtx, {
        type: 'bar',
        data: {
            labels: ['Logs Processed', 'Network Events', 'Endpoint Events', 'Threats Detected', 'Incidents Resolved'],
            datasets: [{
                label: 'System Statistics',
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    'rgba(54, 162, 235, 0.5)',
                    'rgba(255, 206, 86, 0.5)',
                    'rgba(75, 192, 192, 0.5)',
                    'rgba(255, 99, 132, 0.5)',
                    'rgba(153, 102, 255, 0.5)'
                ],
                borderColor: [
                    'rgba(54, 162, 235, 1)',
                    'rgba(255, 206, 86, 1)',
                    'rgba(75, 192, 192, 1)',
                    'rgba(255, 99, 132, 1)',
                    'rgba(153, 102, 255, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
    
    // Initialize alerts chart
    const alertsCtx = document.getElementById('alerts-chart').getContext('2d');
    alertsChart = new Chart(alertsCtx, {
        type: 'pie',
        data: {
            labels: ['Log Anomalies', 'Network Anomalies', 'Endpoint Anomalies'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.7)',
                    'rgba(54, 162, 235, 0.7)',
                    'rgba(255, 206, 86, 0.7)'
                ]
            }]
        },
        options: {
            responsive: true
        }
    });
    
    // Initialize alerts table
    alertsTable = new DataTable('#alerts-table', {
        columns: [
            { title: 'ID' },
            { title: 'Timestamp' },
            { title: 'Source' },
            { title: 'Severity' },
            { title: 'Status' },
            { title: 'Actions' }
        ],
        data: []
    });
    
    // Initial data fetch
    refreshDashboardData();
}

function refreshDashboardData() {
    // Update status indicator
    const statusIndicator = document.getElementById('refresh-status');
    statusIndicator.textContent = 'Refreshing...';
    statusIndicator.className = 'status-refreshing';
    
    // Get timeframe selection
    const timeframe = document.getElementById('timeframe-selector').value;
    
    // Fetch statistics data
    fetch(`/api/stats?timeframe=${timeframe}`)
        .then(response => response.json())
        .then(data => {
            updateStatsChart(data);
            statusIndicator.textContent = 'Data refreshed';
            statusIndicator.className = 'status-success';
            
            // Reset status after 3 seconds
            setTimeout(() => {
                statusIndicator.textContent = 'Idle';
                statusIndicator.className = '';
            }, 3000);
        })
        .catch(error => {
            console.error('Error fetching stats:', error);
            statusIndicator.textContent = 'Refresh failed';
            statusIndicator.className = 'status-error';
        });
    
    // Fetch alerts data
    fetch(`/api/alerts?timeframe=${timeframe}`)
        .then(response => response.json())
        .then(data => {
            updateAlertsChart(data);
            updateAlertsTable(data);
        })
        .catch(error => {
            console.error('Error fetching alerts:', error);
        });
}

function updateStatsChart(data) {
    statsChart.data.datasets[0].data = [
        data.logs_processed,
        data.network_events,
        data.endpoint_events,
        data.threats_detected,
        data.incidents_resolved
    ];
    statsChart.update();
    
    // Update summary numbers
    document.getElementById('total-events').textContent = 
        data.logs_processed + data.network_events + data.endpoint_events;
    document.getElementById('total-alerts').textContent = data.threats_detected;
    document.getElementById('total-incidents').textContent = data.incidents_resolved;
}

function updateAlertsChart(alerts) {
    // Count alerts by source
    const logAlerts = alerts.filter(a => a.source === 'log').length;
    const networkAlerts = alerts.filter(a => a.source === 'network').length;
    const endpointAlerts = alerts.filter(a => a.source === 'endpoint').length;
    
    alertsChart.data.datasets[0].data = [logAlerts, networkAlerts, endpointAlerts];
    alertsChart.update();
}

function updateAlertsTable(alerts) {
    // Clear existing data
    alertsTable.clear();
    
    // Add new rows
    alerts.forEach(alert => {
        const actions = createActionButtons(alert);
        
        alertsTable.row.add([
            alert.id.substring(0, 8), // Truncate UUID for display
            formatTimestamp(alert.timestamp),
            capitalizeFirstLetter(alert.source),
            createSeverityBadge(alert.severity),
            createStatusBadge(alert.status),
            actions
        ]);
    });
    
    alertsTable.draw();
}

function createSeverityBadge(severity) {
    const colors = {
        'high': 'danger',
        'medium': 'warning',
        'low': 'info'
    };
    const colorClass = colors[severity] || 'secondary';
    return `<span class="badge bg-${colorClass}">${capitalizeFirstLetter(severity)}</span>`;
}

function createStatusBadge(status) {
    const colors = {
        'new': 'primary',
        'in_progress': 'info',
        'resolved': 'success',
        'partially_resolved': 'warning',
        'manually_handled': 'info'
    };
    const colorClass = colors[status] || 'secondary';
    return `<span class="badge bg-${colorClass}">${formatStatus(status)}</span>`;
}

function createActionButtons(alert) {
    if (alert.status === 'resolved') {
        return '<span class="text-muted">No actions needed</span>';
    }
    
    return `
        <div class="btn-group btn-group-sm">
            <button class="btn btn-outline-primary response-action" 
                    data-incident-id="${alert.id}" 
                    data-action="investigate">Investigate</button>
            <button class="btn btn-outline-danger response-action" 
                    data-incident-id="${alert.id}" 
                    data-action="contain">Contain</button>
        </div>
    `;
}

function handleResponseAction(incidentId, action) {
    const actionConfig = {
        'investigate': {
            type: 'ticket',
            system: 'jira',
            priority: 'medium'
        },
        'contain': {
            type: action === 'network' ? 'block_ip' : 'isolate_host',
            duration: 7200 // 2 hours
        }
    };
    
    fetch('/api/respond', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            incident_id: incidentId,
            action: actionConfig[action]
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            showToast('Success', `Action "${action}" executed successfully`, 'success');
            refreshDashboardData();
        } else {
            showToast('Error', `Failed to execute action: ${data.message}`, 'error');
        }
    })
    .catch(error => {
        console.error('Error executing action:', error);
        showToast('Error', 'Failed to communicate with server', 'error');
    });
}

function showToast(title, message, type) {
    const toastContainer = document.getElementById('toast-container');
    const toast = document.createElement('div');
    
    toast.className = `toast align-items-center text-white bg-${type === 'error' ? 'danger' : 'success'} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <strong>${title}:</strong> ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    // Remove toast after it's hidden
    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });
}

// Helper functions
function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.replace(/_/g, ' ').slice(1);
}

function formatStatus(status) {
    return status.replace(/_/g, ' ').split(' ').map(capitalizeFirstLetter).join(' ');
}
