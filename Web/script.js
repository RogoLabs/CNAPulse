/**
 * CNA Anomaly Monitor - Frontend Script
 * Loads and displays anomaly data from JSON
 */

// Dark mode
function toggleDarkMode() {
  const isDark = document.documentElement.classList.toggle("dark");
  localStorage.setItem("cnapulse-dark-mode", isDark ? "dark" : "light");
  updateDarkModeIcons();
}
function updateDarkModeIcons() {
  const isDark = document.documentElement.classList.contains("dark");
  const darkIcon = document.getElementById("dark-icon");
  const lightIcon = document.getElementById("light-icon");
  if (darkIcon) darkIcon.classList.toggle("hidden", isDark);
  if (lightIcon) lightIcon.classList.toggle("hidden", !isDark);
}
function initDarkMode() {
  const stored = localStorage.getItem("cnapulse-dark-mode");
  if (
    stored === "dark" ||
    (!stored && window.matchMedia("(prefers-color-scheme: dark)").matches)
  ) {
    document.documentElement.classList.add("dark");
  }
  updateDarkModeIcons();
}
initDarkMode();

// Global variables
let allCNAs = [];
let filteredCNAs = [];
let currentSort = { column: null, direction: "asc" };
let activeStatusFilter = null;
const PAGE_SIZE = 50;
let currentPage = 1;

// Load anomaly data on page load
document.addEventListener("DOMContentLoaded", async () => {
  try {
    await loadAnomalyData();
    readStateFromURL();
    filterAndDisplay();

    // Setup search listener
    document.getElementById("cna-search").addEventListener("input", () => {
      filterAndDisplay();
      writeStateToURL();
    });
  } catch (error) {
    console.error("Error loading anomaly data:", error);
    showError("Failed to load anomaly data. Please try again later.");
  }
});

/**
 * Load anomaly data from JSON file
 */
async function loadAnomalyData() {
  try {
    // Load full data (includes timeline for sparklines)
    // Fall back to summary.json if full data unavailable
    let response = await fetch("anomaly_data.json");
    if (!response.ok) {
      response = await fetch("summary.json");
    }
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();

    // Store CNAs globally
    allCNAs = data.cnas || [];
    filteredCNAs = [...allCNAs];

    // Update UI with loaded data
    updateMetadata(data.metadata);
    updateMetrics(data.metadata);
    updateCNATable(filteredCNAs);
  } catch (error) {
    console.error("Error fetching anomaly data:", error);
    showError("Could not load anomaly data. The data file may not exist yet.");
  }
}

/**
 * Update metadata section with report information
 */
function updateMetadata(metadata) {
  const metadataDiv = document.getElementById("metadata");

  const generatedDate = new Date(metadata.generated_at);
  const formattedDate = generatedDate.toLocaleString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
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
  document.getElementById("monitoring-window").textContent =
    `${metadata.monitoring_window_days} Days`;
  document.getElementById("baseline-period").textContent =
    `${metadata.baseline_months} Months`;
  document.getElementById("total-cnas").textContent = metadata.total_cnas || 0;
  document.getElementById("cnas-growth").textContent =
    metadata.cnas_growth || 0;
  document.getElementById("cnas-normal").textContent =
    metadata.cnas_normal || 0;
  document.getElementById("cnas-declining").textContent =
    metadata.cnas_declining || 0;
  document.getElementById("cnas-inactive").textContent =
    metadata.cnas_inactive || 0;

  // Show metrics section
  document.getElementById("metrics").style.display = "grid";
}

/**
 * Generate an inline SVG sparkline from timeline data
 */
function generateSparkline(timeline) {
  if (!timeline || timeline.length === 0) return "";

  const width = 80;
  const height = 24;
  const padding = 2;

  const values = timeline.map((t) => t.count);
  const max = Math.max(...values, 1);

  const points = values
    .map((val, i) => {
      const x = padding + (i / (values.length - 1)) * (width - 2 * padding);
      const y = height - padding - (val / max) * (height - 2 * padding);
      return `${x},${y}`;
    })
    .join(" ");

  const lastPoint = values[values.length - 1];
  const prevAvg =
    values.slice(0, -1).reduce((a, b) => a + b, 0) /
    Math.max(values.length - 1, 1);
  const color = lastPoint >= prevAvg ? "#3b82f6" : "#6366f1";

  return `<svg width="${width}" height="${height}" class="inline-block"><polyline points="${points}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}

/**
 * Update CNA table with data
 */
function updateCNATable(cnas) {
  const tableBody = document.getElementById("cna-table");

  if (!cnas || cnas.length === 0) {
    tableBody.innerHTML = `
            <tr>
                <td colspan="7" class="px-6 py-4 text-center text-gray-500">
                    No CNAs match your search criteria.
                </td>
            </tr>
        `;
    return;
  }

  // Build table rows
  const rows = cnas
    .map((cna, index) => {
      // Simple striped table with blue-toned status badges
      const rowBg =
        index % 2 === 0
          ? "bg-white dark:bg-gray-800"
          : "bg-gray-50 dark:bg-gray-900";

      // Blue gradient badges for visual appeal
      let badgeColor;
      if (cna.status === "Growth") {
        badgeColor = "bg-blue-100 text-blue-700";
      } else if (cna.status === "Normal") {
        badgeColor = "bg-cyan-100 text-cyan-700";
      } else if (cna.status === "Declining") {
        badgeColor = "bg-indigo-100 text-indigo-700";
      } else if (cna.status === "Inactive") {
        badgeColor = "bg-slate-100 text-slate-700";
      } else {
        badgeColor = "bg-gray-100 text-gray-700";
      }

      const statusText = cna.status;

      // Format deviation percentage
      let deviationText;
      if (cna.deviation_pct >= 999999) {
        deviationText = "∞"; // Infinity symbol for new CNAs (0 baseline, now active)
      } else if (
        cna.deviation_pct === 0 &&
        cna.baseline_avg === 0 &&
        cna.current_count === 0
      ) {
        deviationText = "N/A"; // Inactive CNAs
      } else {
        const deviationSign = cna.deviation_pct > 0 ? "+" : "";
        deviationText = `${deviationSign}${cna.deviation_pct}%`;
      }

      // Format days since last CVE - neutral styling
      let daysSinceText = "Unknown";
      let daysSinceColor = "text-gray-600 dark:text-gray-400";
      if (
        cna.days_since_last_cve !== null &&
        cna.days_since_last_cve !== undefined
      ) {
        daysSinceText = cna.days_since_last_cve;
        daysSinceColor = "text-gray-900 dark:text-gray-100"; // Neutral dark gray for all
      } else if (cna.baseline_avg === 0 && cna.current_count === 0) {
        // Completely inactive CNA
        daysSinceText = "Inactive";
        daysSinceColor = "text-gray-500 dark:text-gray-400 italic";
      }

      // Display full organization name if available, otherwise show short name
      const displayName = cna.cna_org_name || cna.cna_name;
      const subtitle = cna.cna_org_name ? cna.cna_name : null;

      // Make CNA name a link to detail page
      const detailUrl = `cna-detail.html?cna=${encodeURIComponent(cna.cna_name)}`;
      const nameHtml = `<a href="${detailUrl}" class="text-gray-900 dark:text-gray-100 hover:text-blue-600 hover:underline font-medium">${escapeHtml(displayName)}</a>`;

      // Advisory link as separate small link
      let advisoryLinkHtml = "";
      if (cna.cna_advisory_url) {
        advisoryLinkHtml = `<a href="${escapeHtml(cna.cna_advisory_url)}" target="_blank" rel="noopener noreferrer" class="text-xs text-gray-500 dark:text-gray-400 hover:text-blue-600 ml-2" title="Security Advisories">
                <svg class="w-3 h-3 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path>
                </svg>
            </a>`;
      }

      return `
            <tr class="border-b ${rowBg} hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors">
                <td class="px-6 py-4">
                    <div>${nameHtml}</div>
                    ${subtitle ? `<div class="text-sm text-gray-500 dark:text-gray-400">${escapeHtml(subtitle)}${advisoryLinkHtml}</div>` : advisoryLinkHtml ? `<div class="text-sm text-gray-500 dark:text-gray-400">${advisoryLinkHtml}</div>` : ""}
                </td>
                <td class="px-6 py-4">
                    <span class="px-3 py-1 text-xs font-semibold rounded-full ${badgeColor}">
                        ${statusText}
                    </span>
                </td>
                <td class="px-6 py-4 text-gray-900 dark:text-gray-100">${cna.baseline_avg}</td>
                <td class="px-6 py-4 text-gray-900 dark:text-gray-100 font-semibold">${cna.current_count}</td>
                <td class="px-6 py-4">${generateSparkline(cna.timeline_13months)}</td>
                <td class="px-6 py-4 ${daysSinceColor}">${daysSinceText}</td>
                <td class="px-6 py-4 text-gray-900 dark:text-gray-100 font-semibold">${deviationText}</td>
            </tr>
        `;
    })
    .join("");

  tableBody.innerHTML = rows;
}

/**
 * Filter and display CNAs based on search
 */
function filterAndDisplay() {
  const searchTerm = document.getElementById("cna-search").value.toLowerCase();

  filteredCNAs = [...allCNAs];

  if (activeStatusFilter) {
    filteredCNAs = filteredCNAs.filter(
      (cna) => cna.status === activeStatusFilter,
    );
  }

  if (searchTerm) {
    filteredCNAs = filteredCNAs.filter((cna) => {
      const name = (cna.cna_name || "").toLowerCase();
      const orgName = (cna.cna_org_name || "").toLowerCase();
      const assignerId = (cna.assigner_id || "").toLowerCase();
      return (
        name.includes(searchTerm) ||
        orgName.includes(searchTerm) ||
        assignerId.includes(searchTerm)
      );
    });
  }

  if (currentSort.column) {
    applySorting();
  }

  currentPage = 1;
  updateCNATable(getPagedCNAs());
  updatePagination();
  writeStateToURL();
}

/**
 * Filter table by clicking status cards
 */
function filterByStatus(status) {
  if (activeStatusFilter === status) {
    activeStatusFilter = null;
  } else {
    activeStatusFilter = status;
  }

  ["Growth", "Normal", "Declining", "Inactive"].forEach((s) => {
    const card = document.getElementById(`card-${s.toLowerCase()}`);
    if (card) {
      if (activeStatusFilter === s) {
        card.classList.add("ring-2", "ring-offset-2", "ring-blue-500");
      } else {
        card.classList.remove("ring-2", "ring-offset-2", "ring-blue-500");
      }
    }
  });

  filterAndDisplay();
  writeStateToURL();
}

/**
 * Sort table by column
 */
function sortTable(column) {
  // Toggle direction if clicking same column, otherwise ascending
  if (currentSort.column === column) {
    currentSort.direction = currentSort.direction === "asc" ? "desc" : "asc";
  } else {
    currentSort.column = column;
    currentSort.direction = "asc";
  }

  applySorting();
  currentPage = 1;
  updateCNATable(getPagedCNAs());
  updatePagination();
  writeStateToURL();
}

/**
 * Apply current sort to filtered CNAs
 */
function applySorting() {
  const column = currentSort.column;
  const direction = currentSort.direction;
  const multiplier = direction === "asc" ? 1 : -1;

  filteredCNAs.sort((a, b) => {
    let aVal = a[column];
    let bVal = b[column];

    // Handle special cases
    if (column === "cna_name") {
      aVal = (a.cna_org_name || a.cna_name || "").toLowerCase();
      bVal = (b.cna_org_name || b.cna_name || "").toLowerCase();
      return aVal.localeCompare(bVal) * multiplier;
    }

    if (column === "status") {
      // Custom order: Growth, Normal, Declining, Inactive
      const statusOrder = { Growth: 1, Normal: 2, Declining: 3, Inactive: 4 };
      aVal = statusOrder[aVal] || 999;
      bVal = statusOrder[bVal] || 999;
    }

    if (column === "days_since_last_cve") {
      // Handle null values (put them at end)
      if (aVal === null || aVal === undefined) aVal = 999999;
      if (bVal === null || bVal === undefined) bVal = 999999;
    }

    // Numeric comparison
    if (typeof aVal === "number" && typeof bVal === "number") {
      return (aVal - bVal) * multiplier;
    }

    // String comparison
    return String(aVal).localeCompare(String(bVal)) * multiplier;
  });
}

/**
 * Get CNAs for current page
 */
function getPagedCNAs() {
  const start = (currentPage - 1) * PAGE_SIZE;
  const end = start + PAGE_SIZE;
  return filteredCNAs.slice(start, end);
}

/**
 * Update pagination controls
 */
function updatePagination() {
  const totalPages = Math.ceil(filteredCNAs.length / PAGE_SIZE);
  const paginationDiv = document.getElementById("pagination");

  if (filteredCNAs.length <= PAGE_SIZE) {
    paginationDiv.style.display = "none";
    return;
  }

  paginationDiv.style.display = "flex";

  const start = (currentPage - 1) * PAGE_SIZE + 1;
  const end = Math.min(currentPage * PAGE_SIZE, filteredCNAs.length);
  document.getElementById("page-info").textContent =
    `Showing ${start}-${end} of ${filteredCNAs.length} CNAs`;

  document.getElementById("btn-prev").disabled = currentPage === 1;
  document.getElementById("btn-next").disabled = currentPage === totalPages;
}

/**
 * Navigate to next page
 */
function nextPage() {
  const totalPages = Math.ceil(filteredCNAs.length / PAGE_SIZE);
  if (currentPage < totalPages) {
    currentPage++;
    updateCNATable(getPagedCNAs());
    updatePagination();
  }
}

/**
 * Navigate to previous page
 */
function prevPage() {
  if (currentPage > 1) {
    currentPage--;
    updateCNATable(getPagedCNAs());
    updatePagination();
  }
}

/**
 * Read state from URL query params
 */
function readStateFromURL() {
  const params = new URLSearchParams(window.location.search);

  const search = params.get("q");
  if (search) {
    document.getElementById("cna-search").value = search;
  }

  const status = params.get("status");
  if (
    status &&
    ["Growth", "Normal", "Declining", "Inactive"].includes(status)
  ) {
    activeStatusFilter = status;
    const card = document.getElementById(`card-${status.toLowerCase()}`);
    if (card) {
      card.classList.add("ring-2", "ring-offset-2", "ring-blue-500");
    }
  }

  const sortCol = params.get("sort");
  const sortDir = params.get("dir");
  if (sortCol) {
    currentSort.column = sortCol;
    currentSort.direction = sortDir || "asc";
  }
}

/**
 * Write current state to URL query params (without page reload)
 */
function writeStateToURL() {
  const params = new URLSearchParams();

  const search = document.getElementById("cna-search").value;
  if (search) params.set("q", search);
  if (activeStatusFilter) params.set("status", activeStatusFilter);
  if (currentSort.column) {
    params.set("sort", currentSort.column);
    params.set("dir", currentSort.direction);
  }

  const newURL = params.toString()
    ? `${window.location.pathname}?${params.toString()}`
    : window.location.pathname;

  window.history.replaceState({}, "", newURL);
}

/**
 * Show error message
 */
function showError(message) {
  const tableBody = document.getElementById("cna-table");
  tableBody.innerHTML = `
        <tr>
            <td colspan="7" class="px-6 py-4 text-center">
                <div class="text-red-600 font-medium">${escapeHtml(message)}</div>
            </td>
        </tr>
    `;

  const metadataDiv = document.getElementById("metadata");
  metadataDiv.innerHTML = `
        <div class="text-red-600">${escapeHtml(message)}</div>
    `;
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Export filtered CNAs as CSV
 */
function exportCSV() {
  const headers = [
    "CNA Name",
    "Organization",
    "Status",
    "Baseline Avg",
    "Current Count",
    "Days Since Last CVE",
    "Deviation %",
    "Country",
  ];
  const rows = filteredCNAs.map((cna) => [
    cna.cna_name,
    cna.cna_org_name || "",
    cna.status,
    cna.baseline_avg,
    cna.current_count,
    cna.days_since_last_cve ?? "",
    cna.deviation_pct >= 999999 ? "Infinity" : cna.deviation_pct,
    cna.country || "",
  ]);

  const csv = [headers, ...rows]
    .map((row) =>
      row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(","),
    )
    .join("\n");

  downloadFile(csv, "cnapulse-export.csv", "text/csv");
}

/**
 * Export filtered CNAs as JSON
 */
function exportJSON() {
  const data = {
    exported_at: new Date().toISOString(),
    filter: activeStatusFilter || "all",
    search: document.getElementById("cna-search").value || null,
    count: filteredCNAs.length,
    cnas: filteredCNAs.map((cna) => ({
      cna_name: cna.cna_name,
      cna_org_name: cna.cna_org_name,
      status: cna.status,
      baseline_avg: cna.baseline_avg,
      current_count: cna.current_count,
      days_since_last_cve: cna.days_since_last_cve,
      deviation_pct: cna.deviation_pct,
      country: cna.country || "",
    })),
  };

  downloadFile(
    JSON.stringify(data, null, 2),
    "cnapulse-export.json",
    "application/json",
  );
}

/**
 * Trigger browser file download
 */
function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
