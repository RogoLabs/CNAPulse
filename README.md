# CNAPulse 📊

**Monitoring CVE Numbering Authority publishing activity and trends**

## 🌐 Live Dashboard

**[cnapulse.org](https://cnapulse.org)** 

## 🎯 Overview

CNAPulse monitors all **512 official CVE Numbering Authorities (CNAs)** and tracks their publishing activity trends. The dashboard provides real-time insights into CNA publishing patterns, identifying growth, decline, and complete inactivity.

### Key Features

- ✅ **All 512 Official CNAs**: Tracks every registered CNA, not just anomalous ones
- 🔄 **Updates Every 3 Hours**: Fresh data 8 times per day via GitHub Actions
- 📈 **Smart Categorization**: Growth, Normal, Declining, and Inactive status for each CNA
- 🔍 **Real-time Search**: Instantly filter CNAs by name or organization
- 📊 **Sortable Columns**: Click any column header to sort data
- 🔗 **Advisory Links**: Direct links to CNA security advisory pages (315+ CNAs)
- ⏱️ **Days Since Last CVE**: Track CNA publishing recency
- 🎨 **Modern UI**: Responsive design with color-coded status indicators
- 📱 **Mobile-Friendly**: Works seamlessly on all devices

## 🔍 How It Works

### Status Detection

1. **Baseline Calculation**: Analyzes the last 12 months of CVE publications (excluding the current 30-day window) to establish each CNA's historical average monthly publication rate.

2. **Monitoring Window**: Tracks CVE publications in the last 30 days.

3. **Status Classification**: Compares current activity to baseline:
   - **Growth**: Publishing >250% of baseline (+150% growth or more)
   - **Normal**: Publishing 50-250% of baseline (within expected range)
   - **Declining**: Publishing <50% of baseline (-50% decline or more)
   - **Inactive**: No CVEs published in the entire dataset

4. **Enhanced Detection**:
   - **New CNAs**: Shows ∞ (infinity) for CNAs with 0 baseline but recent activity
   - **Complete Inactivity**: Identifies 156 CNAs from the official list with no CVEs
   - **Recent Activity Tracking**: Monitors days since last CVE publication

5. **Report Generation**: Creates a self-contained, interactive HTML dashboard with all 512 CNAs.

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Git
- pip

### Local Usage

1. **Clone the repository**:
   ```bash
   git clone https://github.com/RogoLabs/CNAPulse.git
   cd CNAPulse
   ```

2. **Install dependencies**:
   ```bash
   pip install requests
   ```

3. **Run the analysis**:
   ```bash
   python Code/analyze_cna_anomalies.py
   ```
   
   This will automatically:
   - Download the official CNA list (512 CNAs)
   - Clone the CVEProject/cvelistV5 repository
   - Parse ~310,000 CVE records
   - Analyze all CNA activity
   - Generate `Web/anomaly_data.json`

4. **View the report**:
   ```bash
   cd Web
   python -m http.server 8000
   ```
   Then open http://localhost:8000 in your browser

## 🤖 GitHub Actions Setup

### Enable GitHub Pages

1. Go to your repository **Settings** → **Pages**
2. Under **Source**, select **GitHub Actions**
3. The workflow will automatically deploy on the next run

### Workflow Schedule

The workflow runs:
- **Every 3 hours** (00:00, 03:00, 06:00, 09:00, 12:00, 15:00, 18:00, 21:00 UTC)
- **On push to main branch** (for testing)
- **Manually** (via workflow_dispatch)

This provides **8 updates per day** for fresh, up-to-date CNA activity tracking.

### Manual Trigger

1. Go to **Actions** tab in your repository
2. Select **CNA Anomaly Monitor - Every 3 Hours**
3. Click **Run workflow**

## 📁 Project Structure

```
CNAPulse/
├── Code/                        # Python analysis scripts
│   └── analyze_cna_anomalies.py # Main analysis script (downloads & analyzes CVE data)
├── Web/                         # Web assets (deployed to GitHub Pages)
│   ├── index.html              # Dashboard UI (responsive, sortable, searchable)
│   ├── script.js               # Frontend JavaScript (sorting, filtering, rendering)
│   └── anomaly_data.json       # Generated data (512 CNAs with status, metrics)
├── .github/
│   └── workflows/
│       └── deploy.yml          # GitHub Actions workflow (runs every 3 hours)
├── requirements.txt             # Python dependencies (just requests)
├── cvelistV5/                   # Downloaded CVE data (gitignored, ~310k CVEs)
└── README.md                    # This file
```

## 🛠️ Technical Details

### Data Sources

1. **CVE Data**: [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)
   - Format: CVE JSON 5.0 format
   - ~310,000 CVE records
   - Cloned fresh on every run

2. **Official CNA List**: [CVE Website CNAs List](https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json)
   - 512 registered CNAs
   - Organization names
   - Advisory page URLs
   - Downloaded on every run

### Extracted Data

For each CVE, the script extracts:
- `cveId` - CVE identifier (e.g., CVE-2023-1234)
- `datePublished` - Publication date
- `assignerOrgId` - Unique CNA identifier
- `assignerShortName` - CNA display name (from `containers.cna.providerMetadata.shortName`)

For each CNA, the script calculates:
- 12-month baseline average
- 30-day current activity
- Deviation percentage
- Days since last CVE
- Status (Growth/Normal/Declining/Inactive)

### Dependencies

- **requests**: HTTP library for downloading CNA list and data
- **Standard library**: json, os, subprocess, datetime, pathlib, collections, statistics
- **No pandas required**: Lightweight, fast processing

## 📊 Dashboard Features

The live dashboard at **[cnapulse.org](https://cnapulse.org)** includes:

### Summary Cards
- **Total CNAs**: 512 official CNAs tracked
- **Growth**: CNAs with >250% baseline activity
- **Normal**: CNAs with 50-250% baseline activity
- **Declining**: CNAs with <50% baseline activity
- **Inactive**: CNAs with no CVE publications

### Interactive Table
- **Sortable Columns**: Click any header to sort (CNA Name, Status, Baseline, Current, Days Since Last, Deviation)
- **Search**: Real-time filtering by CNA name or organization
- **Striped Design**: Simple alternating white/gray rows for easy readability without value judgment
- **Neutral Status Badges**: All status indicators use the same gray badge styling
- **Clickable CNA Names**: Direct links to 315+ CNA advisory pages
- **Days Since Last CVE**: Shows days as neutral numbers without color coding
- **Deviation Display**: 
  - Percentages for normal CNAs
  - ∞ (infinity) for new CNAs
  - N/A for inactive CNAs

### Report Metadata
- **Report Generated**: Timestamp with UTC timezone
- **CNAs Analyzed**: Total count (512)
- **Data Source**: Link to CVEProject/cvelistV5
- **RogoLabs Credit**: Project attribution with GitHub link

## 🔧 Configuration

You can modify the following parameters in `Code/analyze_cna_anomalies.py`:

```python
self.monitoring_window = 30   # days for current activity window
self.baseline_months = 12     # months for historical baseline
```

### Status Thresholds

The default thresholds:

```python
threshold_low = avg_monthly * 0.5   # Below 50% of baseline = Declining
threshold_high = avg_monthly * 2.5  # Above 250% of baseline = Growth
# Between 50-250% = Normal
```

## 📈 Use Cases

- **Security Research**: Track publishing patterns across all 512 CNAs and identify trends
- **Vulnerability Management**: Monitor CNA activity to anticipate disclosure volumes
- **CNA Operations**: Benchmark your organization's publishing activity against peers
- **Threat Intelligence**: Identify CNAs with unusual activity patterns
- **Community Transparency**: Public visibility into CNA publishing health
- **Inactive CNA Discovery**: Find 156 CNAs that haven't published any CVEs

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is open source and available under the MIT License.

## 🙏 Acknowledgments

- [CVE Project](https://www.cve.org/) for maintaining the CVE list and CNA registry
- [MITRE Corporation](https://www.mitre.org/) for CVE program management
- All 512 CVE Numbering Authorities for their continuous work in vulnerability disclosure

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/RogoLabs/CNAPulse/issues) page
2. Open a new issue with detailed information
3. Include error messages and logs if applicable

## 🏢 About

**CNAPulse** is a [RogoLabs](https://rogolabs.net/) project dedicated to providing transparency and insights into CVE Numbering Authority activity.

---

**Website**: [cnapulse.org](https://cnapulse.org)  
**GitHub**: [github.com/RogoLabs/CNAPulse](https://github.com/RogoLabs/CNAPulse)  
**Updates**: Every 3 hours (8x daily)  
**Last Updated**: 2025-10-16
