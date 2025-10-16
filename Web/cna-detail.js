/**
 * CNA Detail Page - Frontend Script
 */

let chartInstance = null;

// Get CNA name from URL parameter
function getCNAFromURL() {
    const params = new URLSearchParams(window.location.search);
    return params.get('cna');
}

// Load and display CNA data
async function loadCNADetail() {
    const cnaName = getCNAFromURL();
    
    if (!cnaName) {
        showError('No CNA specified in URL');
        return;
    }
    
    try {
        const response = await fetch('anomaly_data.json');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        const cna = data.cnas.find(c => c.cna_name === cnaName);
        
        if (!cna) {
            showError(`CNA "${cnaName}" not found in dataset`);
            return;
        }
        
        displayCNA(cna);
        
    } catch (error) {
        console.error('Error loading CNA data:', error);
        showError('Failed to load CNA data. Please try again later.');
    }
}

// Display CNA information
function displayCNA(cna) {
    // Hide loading, show content
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('cna-content').classList.remove('hidden');
    
    // Set title and subtitle
    const displayName = cna.cna_org_name || cna.cna_name;
    document.getElementById('cna-title').textContent = displayName;
    
    if (cna.cna_org_name) {
        document.getElementById('cna-subtitle').textContent = `CNA ID: ${cna.cna_name}`;
    } else {
        document.getElementById('cna-subtitle').textContent = 'CNA';
    }
    
    // Advisory link
    if (cna.cna_advisory_url) {
        const link = document.getElementById('cna-advisory-link');
        link.href = cna.cna_advisory_url;
        link.classList.remove('hidden');
    }
    
    // Status badge with blue gradient colors
    const statusBadge = document.getElementById('status-badge');
    statusBadge.textContent = cna.status;
    
    // Match the color scheme from the main dashboard
    statusBadge.className = 'px-3 py-1 text-xs font-semibold rounded-full ';
    if (cna.status === 'Growth') {
        statusBadge.className += 'bg-blue-100 text-blue-700';
    } else if (cna.status === 'Normal') {
        statusBadge.className += 'bg-cyan-100 text-cyan-700';
    } else if (cna.status === 'Declining') {
        statusBadge.className += 'bg-indigo-100 text-indigo-700';
    } else if (cna.status === 'Inactive') {
        statusBadge.className += 'bg-slate-100 text-slate-700';
    } else {
        statusBadge.className += 'bg-gray-100 text-gray-700';
    }
    
    // Metrics
    document.getElementById('metric-baseline').textContent = cna.baseline_avg.toFixed(1);
    document.getElementById('metric-current').textContent = cna.current_count;
    
    // Deviation
    let deviationText;
    if (cna.deviation_pct >= 999999) {
        deviationText = '∞';
    } else if (cna.deviation_pct === 0 && cna.baseline_avg === 0 && cna.current_count === 0) {
        deviationText = 'N/A';
    } else {
        const sign = cna.deviation_pct > 0 ? '+' : '';
        deviationText = `${sign}${cna.deviation_pct}%`;
    }
    document.getElementById('metric-deviation').textContent = deviationText;
    
    // Days since last CVE
    let daysText;
    if (cna.days_since_last_cve !== null && cna.days_since_last_cve !== undefined) {
        daysText = cna.days_since_last_cve;
    } else if (cna.baseline_avg === 0 && cna.current_count === 0) {
        daysText = 'Inactive';
    } else {
        daysText = 'Unknown';
    }
    document.getElementById('metric-days').textContent = daysText;
    
    // Create chart
    renderTimelineChart(cna);
}

// Render the 13-month timeline chart
function renderTimelineChart(cna) {
    const ctx = document.getElementById('timeline-chart');
    
    if (!cna.timeline_13months || cna.timeline_13months.length === 0) {
        ctx.parentElement.innerHTML = '<p class="text-gray-500 text-center py-12">No timeline data available</p>';
        return;
    }
    
    const labels = cna.timeline_13months.map(t => t.month);
    const data = cna.timeline_13months.map(t => t.count);
    const isCurrent = cna.timeline_13months.map(t => t.is_current);
    
    // Color coding: baseline months are gray, current month is blue
    const backgroundColors = isCurrent.map(current => 
        current ? 'rgba(59, 130, 246, 0.6)' : 'rgba(156, 163, 175, 0.6)'
    );
    const borderColors = isCurrent.map(current =>
        current ? 'rgba(59, 130, 246, 1)' : 'rgba(156, 163, 175, 1)'
    );
    
    // Create average line data (baseline average repeated for all 13 months)
    const baselineAvg = cna.baseline_avg;
    const avgLineData = new Array(13).fill(baselineAvg);
    
    // Destroy existing chart if any
    if (chartInstance) {
        chartInstance.destroy();
    }
    
    chartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'CVE Publications',
                    data: data,
                    backgroundColor: backgroundColors,
                    borderColor: borderColors,
                    borderWidth: 2,
                    order: 2
                },
                {
                    label: '12-Month Average',
                    data: avgLineData,
                    type: 'line',
                    borderColor: 'rgba(37, 99, 235, 1)',
                    backgroundColor: 'rgba(37, 99, 235, 0.1)',
                    borderWidth: 3,
                    borderDash: [8, 4],
                    pointRadius: 0,
                    pointHoverRadius: 0,
                    fill: false,
                    order: 1
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    labels: {
                        usePointStyle: true,
                        boxWidth: 20,
                        padding: 15
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const datasetLabel = context.dataset.label;
                            const value = context.parsed.y;
                            
                            if (datasetLabel === '12-Month Average') {
                                return `${datasetLabel}: ${value.toFixed(1)} CVEs`;
                            } else {
                                const label = isCurrent[context.dataIndex] ? ' (Current Period)' : '';
                                return `${value} CVE${value !== 1 ? 's' : ''}${label}`;
                            }
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1,
                        callback: function(value) {
                            if (Number.isInteger(value)) {
                                return value;
                            }
                        }
                    },
                    title: {
                        display: true,
                        text: 'Number of CVEs Published'
                    }
                },
                x: {
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45
                    }
                }
            }
        }
    });
}

// Show error message
function showError(message) {
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('error').classList.remove('hidden');
    document.getElementById('error-message').textContent = message;
}

// Load on page ready
document.addEventListener('DOMContentLoaded', loadCNADetail);
