/**
 * CNA Anomaly Monitor - Frontend Script
 * Loads and displays anomaly data from JSON
 */

// Global variables
let allCNAs = [];
let filteredCNAs = [];
let currentSort = { column: null, direction: 'asc' };

// Load anomaly data on page load
document.addEventListener('DOMContentLoaded', async () => {
    try {
        await loadAnomalyData();
        
        // Setup search listener
        document.getElementById('cna-search').addEventListener('input', filterAndDisplay);
    } catch (error) {
        console.error('Error loading anomaly data:', error);
        showError('Failed to load anomaly data. Please try again later.');
    }
});

/**
 * Load anomaly data from JSON file
 */
async function loadAnomalyData() {
    try {
        const response = await fetch('anomaly_data.json');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        
        // Store CNAs globally
        allCNAs = data.cnas || data.anomalies || [];
        filteredCNAs = [...allCNAs];  // Initial filtered view is all CNAs
        
        // Update UI with loaded data
        updateMetadata(data.metadata);
        updateMetrics(data.metadata);
        updateCNATable(filteredCNAs);
        
    } catch (error) {
        console.error('Error fetching anomaly data:', error);
        showError('Could not load anomaly data. The data file may not exist yet.');
    }
}

/**
 * Update metadata section with report information
 */
function updateMetadata(metadata) {
    const metadataDiv = document.getElementById('metadata');
    
    const generatedDate = new Date(metadata.generated_at);
    const formattedDate = generatedDate.toLocaleString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        timeZone: 'UTC',
        timeZoneName: 'short'
    });
    
    metadataDiv.innerHTML = `
        <div class="flex items-center gap-2">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
            </svg>
            <span>Report Generated: ${formattedDate}</span>
        </div>
        <div class="flex items-center gap-2">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
            </svg>
            <span>CNAs Analyzed: ${metadata.total_cnas || 0}</span>
        </div>
    `;
}

/**
 * Update metric cards
 */
function updateMetrics(metadata) {
    document.getElementById('monitoring-window').textContent = `${metadata.monitoring_window_days} Days`;
    document.getElementById('baseline-period').textContent = `${metadata.baseline_months} Months`;
    document.getElementById('total-cnas').textContent = metadata.total_cnas || 0;
    document.getElementById('cnas-growth').textContent = metadata.cnas_growth || 0;
    document.getElementById('cnas-normal').textContent = metadata.cnas_normal || 0;
    document.getElementById('cnas-declining').textContent = metadata.cnas_declining || 0;
    document.getElementById('cnas-inactive').textContent = metadata.cnas_inactive || 0;
    
    // Show metrics section
    document.getElementById('metrics').style.display = 'grid';
}

/**
 * Update CNA table with data
 */
function updateCNATable(cnas) {
    const tableBody = document.getElementById('cna-table');
    
    if (!cnas || cnas.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="6" class="px-6 py-4 text-center text-gray-500">
                    No CNAs match your search criteria.
                </td>
            </tr>
        `;
        return;
    }
    
    // Build table rows
    const rows = cnas.map((cna, index) => {
        // Simple striped table with blue-toned status badges
        const rowBg = index % 2 === 0 ? 'bg-white' : 'bg-gray-50';
        
        // Blue gradient badges for visual appeal
        let badgeColor;
        if (cna.status === 'Growth') {
            badgeColor = 'bg-blue-100 text-blue-700';
        } else if (cna.status === 'Normal') {
            badgeColor = 'bg-cyan-100 text-cyan-700';
        } else if (cna.status === 'Declining') {
            badgeColor = 'bg-indigo-100 text-indigo-700';
        } else if (cna.status === 'Inactive') {
            badgeColor = 'bg-slate-100 text-slate-700';
        } else {
            badgeColor = 'bg-gray-100 text-gray-700';
        }
        
        const statusText = cna.status;
        
        // Format deviation percentage
        let deviationText;
        if (cna.deviation_pct >= 999999) {
            deviationText = '∞';  // Infinity symbol for new CNAs (0 baseline, now active)
        } else if (cna.deviation_pct === 0 && cna.baseline_avg === 0 && cna.current_count === 0) {
            deviationText = 'N/A';  // Inactive CNAs
        } else {
            const deviationSign = cna.deviation_pct > 0 ? '+' : '';
            deviationText = `${deviationSign}${cna.deviation_pct}%`;
        }
        
        // Format days since last CVE - neutral styling
        let daysSinceText = 'Unknown';
        let daysSinceColor = 'text-gray-600';
        if (cna.days_since_last_cve !== null && cna.days_since_last_cve !== undefined) {
            daysSinceText = cna.days_since_last_cve;
            daysSinceColor = 'text-gray-900';  // Neutral dark gray for all
        } else if (cna.baseline_avg === 0 && cna.current_count === 0) {
            // Completely inactive CNA
            daysSinceText = 'Inactive';
            daysSinceColor = 'text-gray-500 italic';
        }
        
        // Display full organization name if available, otherwise show short name
        const displayName = cna.cna_org_name || cna.cna_name;
        const subtitle = cna.cna_org_name ? cna.cna_name : null;
        
        // Make CNA name a link to detail page
        const detailUrl = `cna-detail.html?cna=${encodeURIComponent(cna.cna_name)}`;
        const nameHtml = `<a href="${detailUrl}" class="text-gray-900 hover:text-blue-600 hover:underline font-medium">${escapeHtml(displayName)}</a>`;
        
        // Advisory link as separate small link
        let advisoryLinkHtml = '';
        if (cna.cna_advisory_url) {
            advisoryLinkHtml = `<a href="${escapeHtml(cna.cna_advisory_url)}" target="_blank" rel="noopener noreferrer" class="text-xs text-gray-500 hover:text-blue-600 ml-2" title="Security Advisories">
                <svg class="w-3 h-3 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path>
                </svg>
            </a>`;
        }
        
        return `
            <tr class="border-b ${rowBg} hover:bg-gray-100 transition-colors">
                <td class="px-6 py-4">
                    <div>${nameHtml}</div>
                    ${subtitle ? `<div class="text-sm text-gray-500">${escapeHtml(subtitle)}${advisoryLinkHtml}</div>` : (advisoryLinkHtml ? `<div class="text-sm text-gray-500">${advisoryLinkHtml}</div>` : '')}
                </td>
                <td class="px-6 py-4">
                    <span class="px-3 py-1 text-xs font-semibold rounded-full ${badgeColor}">
                        ${statusText}
                    </span>
                </td>
                <td class="px-6 py-4 text-gray-900">${cna.baseline_avg}</td>
                <td class="px-6 py-4 text-gray-900 font-semibold">${cna.current_count}</td>
                <td class="px-6 py-4 ${daysSinceColor}">${daysSinceText}</td>
                <td class="px-6 py-4 text-gray-900 font-semibold">${deviationText}</td>
            </tr>
        `;
    }).join('');
    
    tableBody.innerHTML = rows;
}

/**
 * Filter and display CNAs based on search
 */
function filterAndDisplay() {
    const searchTerm = document.getElementById('cna-search').value.toLowerCase();
    
    // Apply search filter
    if (searchTerm) {
        filteredCNAs = allCNAs.filter(cna => {
            const name = (cna.cna_name || '').toLowerCase();
            const orgName = (cna.cna_org_name || '').toLowerCase();
            const assignerId = (cna.assigner_id || '').toLowerCase();
            
            return name.includes(searchTerm) || 
                   orgName.includes(searchTerm) || 
                   assignerId.includes(searchTerm);
        });
    } else {
        filteredCNAs = [...allCNAs];
    }
    
    // Reapply current sort if any
    if (currentSort.column) {
        applySorting();
    }
    
    updateCNATable(filteredCNAs);
}

/**
 * Sort table by column
 */
function sortTable(column) {
    // Toggle direction if clicking same column, otherwise ascending
    if (currentSort.column === column) {
        currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
    } else {
        currentSort.column = column;
        currentSort.direction = 'asc';
    }
    
    applySorting();
    updateCNATable(filteredCNAs);
}

/**
 * Apply current sort to filtered CNAs
 */
function applySorting() {
    const column = currentSort.column;
    const direction = currentSort.direction;
    const multiplier = direction === 'asc' ? 1 : -1;
    
    filteredCNAs.sort((a, b) => {
        let aVal = a[column];
        let bVal = b[column];
        
        // Handle special cases
        if (column === 'cna_name') {
            aVal = (a.cna_org_name || a.cna_name || '').toLowerCase();
            bVal = (b.cna_org_name || b.cna_name || '').toLowerCase();
            return aVal.localeCompare(bVal) * multiplier;
        }
        
        if (column === 'status') {
            // Custom order: Growth, Normal, Declining, Inactive
            const statusOrder = { 'Growth': 1, 'Normal': 2, 'Declining': 3, 'Inactive': 4 };
            aVal = statusOrder[aVal] || 999;
            bVal = statusOrder[bVal] || 999;
        }
        
        if (column === 'days_since_last_cve') {
            // Handle null values (put them at end)
            if (aVal === null || aVal === undefined) aVal = 999999;
            if (bVal === null || bVal === undefined) bVal = 999999;
        }
        
        // Numeric comparison
        if (typeof aVal === 'number' && typeof bVal === 'number') {
            return (aVal - bVal) * multiplier;
        }
        
        // String comparison
        return String(aVal).localeCompare(String(bVal)) * multiplier;
    });
}

/**
 * Show error message
 */
function showError(message) {
    const tableBody = document.getElementById('cna-table');
    tableBody.innerHTML = `
        <tr>
            <td colspan="6" class="px-6 py-4 text-center">
                <div class="text-red-600 font-medium">${escapeHtml(message)}</div>
            </td>
        </tr>
    `;
    
    const metadataDiv = document.getElementById('metadata');
    metadataDiv.innerHTML = `
        <div class="text-red-600">${escapeHtml(message)}</div>
    `;
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
