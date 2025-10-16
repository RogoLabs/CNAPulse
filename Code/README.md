# CNAPulse Code

This directory contains the Python scripts for analyzing CNA publishing anomalies.

## Scripts

### `analyze_cna_anomalies.py`

Main analysis script that processes CVE data and generates anomaly reports.

**Input:**
- CVE data from `cvelistV5/` directory (cloned separately)

**Output:**
- `web/anomaly_data.json` - JSON file containing anomaly data and metadata

**Usage:**
```bash
python code/analyze_cna_anomalies.py
```

## Analysis Logic

### Baseline Calculation
- Analyzes the last 12 months of CVE publications (excluding current 30-day window)
- Calculates average monthly publication rate for each CNA
- Groups publications by month to compute baseline statistics

### Anomaly Detection
- Compares 30-day activity to 12-month baseline
- Uses 1.5 standard deviations as threshold
- Identifies two types of anomalies:
  - **LOW**: Activity below threshold (potential inactivity)
  - **HIGH**: Activity above threshold (potential bulk disclosure)

### Output Format

The generated `anomaly_data.json` contains:

```json
{
  "metadata": {
    "generated_at": "ISO timestamp",
    "monitoring_window_days": 30,
    "baseline_months": 12,
    "total_cnas_analyzed": 123,
    "total_anomalies": 45,
    "anomalies_low": 20,
    "anomalies_high": 25
  },
  "anomalies": [
    {
      "assigner_id": "org@example.com",
      "cna_name": "Example CNA",
      "anomaly_type": "LOW",
      "baseline_avg": 10.5,
      "current_count": 2,
      "deviation_pct": -80.9,
      "std_dev": 2.3,
      "threshold_low": 7.0,
      "threshold_high": 14.0
    }
  ]
}
```

## Dependencies

See `requirements.txt` in the project root.

## Development

To test locally:

1. Clone CVE data:
   ```bash
   git clone --depth 1 https://github.com/CVEProject/cvelistV5.git
   ```

2. Run analysis:
   ```bash
   python code/analyze_cna_anomalies.py
   ```

3. Check output:
   ```bash
   cat web/anomaly_data.json
   ```
