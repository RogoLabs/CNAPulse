#!/usr/bin/env python3
"""
CNA Publishing Anomaly Analysis

Analyzes CVE publishing activity from cvelistV5 and generates anomaly data.
Outputs JSON data files to the web/ directory.

Usage:
    python code/analyze_cna_anomalies.py
"""

import os
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import statistics

try:
    import requests
except ImportError:
    requests = None
    print("Warning: requests module not found. CNA organization names will not be available.")


class CVEMonitor:
    """Main class for CVE monitoring and anomaly detection."""
    
    def __init__(self):
        self.cves_dir = 'cvelistV5/cves'
        self.now = datetime.now()
        self.monitoring_window = 30  # days
        self.baseline_months = 12  # months
        self.cna_org_names = {}  # Map CNA short names to organization names
        self.cna_by_uuid = {}  # Map UUID to CNA info for better matching
        
    def load_cna_organization_names(self):
        """Download and cache CNA organization names from official list."""
        if not requests:
            print("Requests module not available, skipping CNA name lookup")
            return
        
        try:
            print("Downloading official CNA list...")
            url = "https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            cna_list = response.json()
            print(f"Downloaded {len(cna_list)} CNAs from official list")
            
            # Map shortName to organizationName and advisory URL
            for cna in cna_list:
                short_name = cna.get('shortName') or cna.get('ShortName') or cna.get('cnaShortName')
                org_name = cna.get('organizationName', '')
                uuid = cna.get('UUID') or cna.get('uuid')
                
                # Get advisory URL (try multiple locations)
                advisory_url = ''
                
                # Try securityAdvisories.advisories first
                sec_advisories = cna.get('securityAdvisories', {})
                if isinstance(sec_advisories, dict):
                    advisories_list = sec_advisories.get('advisories', [])
                    if advisories_list and len(advisories_list) > 0:
                        advisory_url = advisories_list[0].get('url', '')
                
                # Fallback to top-level advisories
                if not advisory_url:
                    advisories = cna.get('advisories', [])
                    if advisories and len(advisories) > 0:
                        advisory_url = advisories[0].get('url', '')
                
                cna_info = {
                    'org_name': org_name or short_name,
                    'advisory_url': advisory_url,
                    'short_name': short_name,
                    'uuid': uuid
                }
                
                # Index by shortName (exact)
                if short_name:
                    self.cna_org_names[short_name] = cna_info
                    # Also index by lowercase for case-insensitive lookup
                    self.cna_org_names[short_name.lower()] = cna_info
                
                # Index by UUID for more reliable matching
                if uuid:
                    self.cna_by_uuid[uuid] = cna_info
            
            print(f"Mapped {len(self.cna_org_names)} CNA organization names")
            print(f"Mapped {len(self.cna_by_uuid)} CNAs by UUID")
            
        except Exception as e:
            print(f"Warning: Could not download CNA list: {e}")
            print("Will use short names only")
    
    def get_cna_info(self, short_name, assigner_id):
        """
        Look up CNA info with multiple fallback strategies.
        Returns dict with org_name and advisory_url.
        """
        # Try exact match on short name
        if short_name in self.cna_org_names:
            return self.cna_org_names[short_name]
        
        # Try lowercase match
        if short_name and short_name.lower() in self.cna_org_names:
            return self.cna_org_names[short_name.lower()]
        
        # Try UUID match
        if assigner_id in self.cna_by_uuid:
            return self.cna_by_uuid[assigner_id]
        
        # Return default
        return {
            'org_name': short_name or 'Unknown',
            'advisory_url': '',
            'short_name': short_name,
            'uuid': assigner_id
        }
        
    def parse_cve_files(self):
        """
        Recursively parse all CVE JSON files and extract required fields.
        Returns a list of dictionaries with CVE data.
        """
        print(f"Parsing CVE files from {self.cves_dir}...")
        cve_data = []
        
        if not os.path.exists(self.cves_dir):
            print(f"Error: CVEs directory not found: {self.cves_dir}")
            return cve_data
        
        # Recursively find all .json files
        json_files = list(Path(self.cves_dir).rglob("*.json"))
        total_files = len(json_files)
        print(f"Found {total_files} JSON files to process...")
        
        processed = 0
        errors = 0
        
        for json_file in json_files:
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Extract required fields
                cve_metadata = data.get('cveMetadata', {})
                
                # Extract CNA name using CNAScoreCard approach
                # Use containers.cna.providerMetadata.shortName (more accurate)
                containers = data.get('containers', {})
                cna_container = containers.get('cna', {})
                provider_metadata = cna_container.get('providerMetadata', {})
                cna_short_name = provider_metadata.get('shortName')
                
                # Fallback to assignerShortName if providerMetadata not available
                if not cna_short_name:
                    cna_short_name = cve_metadata.get('assignerShortName', 'Unknown')
                
                cve_entry = {
                    'cveId': cve_metadata.get('cveId', 'Unknown'),
                    'datePublished': cve_metadata.get('datePublished', ''),
                    'assignerOrgId': cve_metadata.get('assignerOrgId', 'Unknown'),
                    'assignerShortName': cna_short_name
                }
                
                # Only add if we have a valid date
                if cve_entry['datePublished']:
                    cve_data.append(cve_entry)
                
                processed += 1
                if processed % 10000 == 0:
                    print(f"Processed {processed}/{total_files} files...")
                    
            except (json.JSONDecodeError, KeyError, Exception) as e:
                errors += 1
                if errors <= 10:  # Only print first 10 errors
                    print(f"Error processing {json_file}: {e}")
        
        print(f"Parsing complete. Processed: {processed}, Errors: {errors}")
        print(f"Successfully extracted {len(cve_data)} CVE records")
        return cve_data
    
    def parse_date(self, date_str):
        """Parse ISO date string to datetime object."""
        try:
            # Handle various ISO 8601 formats
            if 'T' in date_str:
                # Remove timezone info for simplicity
                date_str = date_str.split('+')[0].split('Z')[0].split('.')[0]
                return datetime.fromisoformat(date_str)
            else:
                return datetime.fromisoformat(date_str)
        except (ValueError, AttributeError):
            return None
    
    def generate_13month_timeline(self, monthly_data, current_count, monitoring_window_days=30):
        """Generate 13-month timeline: 12 baseline months + current period."""
        # Calculate the last 13 months
        timeline = []
        
        # Start from 12 months ago
        start_date = self.now - timedelta(days=365)  # ~12 months
        
        for i in range(12):
            # Calculate month
            month_date = start_date + timedelta(days=30 * i)
            month_key = (month_date.year, month_date.month)
            
            count = monthly_data.get(month_key, 0)
            month_label = month_date.strftime('%b %Y')
            
            timeline.append({
                'month': month_label,
                'count': count,
                'is_current': False
            })
        
        # Add current 30-day period
        current_label = self.now.strftime('%b %Y') + ' (Current)'
        timeline.append({
            'month': current_label,
            'count': current_count,
            'is_current': True
        })
        
        return timeline
    
    def analyze_cna_activity(self, cve_data):
        """Analyze CNA publishing activity for anomalies."""
        print("\nAnalyzing CNA activity...")
        
        # Calculate date boundaries
        monitoring_start = self.now - timedelta(days=self.monitoring_window)
        baseline_start = self.now - timedelta(days=self.monitoring_window + (self.baseline_months * 30))
        baseline_end = monitoring_start
        recent_activity_cutoff = self.now - timedelta(days=14)  # Check last 14 days for recent activity
        
        print(f"Monitoring window: {monitoring_start.date()} to {self.now.date()}")
        print(f"Baseline period: {baseline_start.date()} to {baseline_end.date()}")
        print(f"Recent activity check: {recent_activity_cutoff.date()} to {self.now.date()}")
        
        # Data structures
        baseline_counts = defaultdict(list)  # {assignerOrgId: [monthly counts]}
        monitoring_counts = defaultdict(int)  # {assignerOrgId: count}
        recent_activity_counts = defaultdict(int)  # {assignerOrgId: count in last 14 days}
        last_cve_dates = {}  # {assignerOrgId: most recent CVE date}
        cna_names = {}  # {assignerOrgId: assignerShortName}
        
        # Process each CVE
        for cve in cve_data:
            date_published = self.parse_date(cve['datePublished'])
            if not date_published:
                continue
            
            assigner_id = cve['assignerOrgId']
            cna_names[assigner_id] = cve['assignerShortName']
            
            # Track most recent CVE date for each CNA (across all time)
            if assigner_id not in last_cve_dates or date_published > last_cve_dates[assigner_id]:
                last_cve_dates[assigner_id] = date_published
            
            # Check if in monitoring window
            if monitoring_start <= date_published <= self.now:
                monitoring_counts[assigner_id] += 1
                
                # Also track recent activity (last 14 days)
                if date_published >= recent_activity_cutoff:
                    recent_activity_counts[assigner_id] += 1
            
            # Check if in baseline period
            elif baseline_start <= date_published < baseline_end:
                baseline_counts[assigner_id].append(date_published)
        
        # Calculate monthly averages for baseline
        cna_baselines = {}
        for assigner_id, dates in baseline_counts.items():
            if dates:
                # Group by month
                monthly_counts = defaultdict(int)
                for date in dates:
                    month_key = (date.year, date.month)
                    monthly_counts[month_key] += 1
                
                # Calculate average
                if monthly_counts:
                    avg_monthly = sum(monthly_counts.values()) / len(monthly_counts)
                    cna_baselines[assigner_id] = {
                        'avg_monthly': avg_monthly,
                        'short_name': cna_names.get(assigner_id, 'Unknown'),
                        'monthly_counts': list(monthly_counts.values()),
                        'monthly_data': dict(monthly_counts)  # Store month keys for timeline
                    }
        
        print(f"Found {len(cna_baselines)} CNAs with baseline data")
        print(f"Found {len(monitoring_counts)} CNAs with recent activity")
        
        # Find CNAs with recent activity but NO baseline (new/newly active CNAs)
        new_cnas = set(monitoring_counts.keys()) - set(cna_baselines.keys())
        print(f"Found {len(new_cnas)} new/newly active CNAs (no baseline data)")
        
        # Find ALL official CNAs that we haven't seen yet (completely inactive)
        all_seen_cna_ids = set(cna_baselines.keys()) | set(monitoring_counts.keys())
        official_cna_names = set(self.cna_org_names.keys())
        
        # Map official names to IDs we've seen
        seen_cna_names = set()
        for cna_id in all_seen_cna_ids:
            name = cna_names.get(cna_id, 'Unknown')
            if name != 'Unknown':
                seen_cna_names.add(name)
        
        # Find CNAs in official list but not in our data
        inactive_cna_names = official_cna_names - seen_cna_names
        print(f"Found {len(inactive_cna_names)} completely inactive CNAs (no CVEs in dataset)")
        
        # Analyze all CNAs (not just anomalies)
        anomalies = []
        all_cnas = []
        
        # Process CNAs with baseline data
        for assigner_id, baseline_info in cna_baselines.items():
            current_count = monitoring_counts.get(assigner_id, 0)
            avg_monthly = baseline_info['avg_monthly']
            monthly_counts = baseline_info['monthly_counts']
            
            # Calculate expected count for monitoring window (30 days ≈ 1 month)
            expected_count = avg_monthly
            
            # Calculate standard deviation if we have enough data
            if len(monthly_counts) >= 3:
                try:
                    std_dev = statistics.stdev(monthly_counts)
                except statistics.StatisticsError:
                    std_dev = 0
            else:
                std_dev = 0
            
            # Status thresholds
            # Normal = within 50% to 250% of baseline (-50% to +150% growth)
            # Declining = below 50% of baseline (below -50% from baseline)
            # Growth = above 250% of baseline (above +150% growth)
            threshold_low = avg_monthly * 0.5  # Below 50% of baseline is Declining
            threshold_high = avg_monthly * 2.5  # Above 250% of baseline is Growth
            
            # Identify status type based on deviation from baseline
            anomaly_type = None
            
            # Growth: Above 250% of baseline (+150% growth)
            if current_count > threshold_high:
                anomaly_type = "Growth"
            
            # Declining: Below 50% of baseline (-50% from baseline)
            # Only flag if baseline was meaningful (>=0.5 CVEs/month)
            elif current_count < threshold_low and avg_monthly >= 0.5:
                anomaly_type = "Declining"
            
            # Otherwise: Normal (within 50% to 250% of baseline)
            
            # Determine status for all CNAs
            if anomaly_type:
                status = anomaly_type  # "Growth" or "Declining"
            else:
                status = "Normal"
            
            deviation_pct = ((current_count - avg_monthly) / avg_monthly * 100) if avg_monthly > 0 else 0
            
            # Calculate days since last CVE
            last_cve_date = last_cve_dates.get(assigner_id)
            if last_cve_date:
                days_since_last = (self.now - last_cve_date).days
                # Clamp to 0 if negative (future dates due to timezone/clock differences)
                if days_since_last < 0:
                    days_since_last = 0
            else:
                days_since_last = None
            
            # Get organization name and advisory URL from official list
            short_name = baseline_info['short_name']
            cna_info = self.get_cna_info(short_name, assigner_id)
            org_name = cna_info.get('org_name', '')
            advisory_url = cna_info.get('advisory_url', '')
            
            # Generate 13-month timeline for detail page
            timeline_13months = self.generate_13month_timeline(
                baseline_info.get('monthly_data', {}),
                current_count
            )
            
            cna_entry = {
                'assigner_id': assigner_id,
                'cna_name': short_name,
                'cna_org_name': org_name,
                'cna_advisory_url': advisory_url,
                'status': status,
                'baseline_avg': round(avg_monthly, 2),
                'current_count': current_count,
                'deviation_pct': round(deviation_pct, 1),
                'days_since_last_cve': days_since_last,
                'std_dev': round(std_dev, 2) if std_dev > 0 else None,
                'threshold_low': round(threshold_low, 2),
                'threshold_high': round(threshold_high, 2),
                'timeline_13months': timeline_13months
            }
            
            # Add to all CNAs list
            all_cnas.append(cna_entry)
            
            # Also add to anomalies list if it's an anomaly
            if anomaly_type:
                anomalies.append(cna_entry)
        
        # Process new/newly active CNAs (0 baseline, recent activity)
        for assigner_id in new_cnas:
            current_count = monitoring_counts.get(assigner_id, 0)
            
            # Skip if no recent activity (shouldn't happen but be safe)
            if current_count == 0:
                continue
            
            # Calculate days since last CVE
            last_cve_date = last_cve_dates.get(assigner_id)
            if last_cve_date:
                days_since_last = (self.now - last_cve_date).days
                # Clamp to 0 if negative (future dates due to timezone/clock differences)
                if days_since_last < 0:
                    days_since_last = 0
            else:
                days_since_last = None
            
            # Get organization name and advisory URL
            short_name = cna_names.get(assigner_id, 'Unknown')
            cna_info = self.get_cna_info(short_name, assigner_id)
            org_name = cna_info.get('org_name', '')
            advisory_url = cna_info.get('advisory_url', '')
            
            # Generate 13-month timeline for new CNAs (all zeros + current)
            timeline_13months = self.generate_13month_timeline({}, current_count)
            
            # New CNAs are marked as "Growth" (went from 0 to something)
            cna_entry = {
                'assigner_id': assigner_id,
                'cna_name': short_name,
                'cna_org_name': org_name,
                'cna_advisory_url': advisory_url,
                'status': 'Growth',
                'baseline_avg': 0.0,
                'current_count': current_count,
                'deviation_pct': 999999.0,  # Large number to represent infinite growth from 0
                'days_since_last_cve': days_since_last,
                'std_dev': None,
                'threshold_low': 0.0,
                'threshold_high': 0.0,
                'timeline_13months': timeline_13months
            }
            
            all_cnas.append(cna_entry)
            anomalies.append(cna_entry)  # New CNAs are anomalies
        
        # Process completely inactive CNAs (in official list but no CVEs in dataset)
        for short_name in inactive_cna_names:
            cna_info = self.get_cna_info(short_name, None)
            org_name = cna_info.get('org_name', short_name)
            advisory_url = cna_info.get('advisory_url', '')
            
            # Generate 13-month timeline for inactive CNAs (all zeros)
            timeline_13months = self.generate_13month_timeline({}, 0)
            
            # Completely inactive CNAs - marked as "Inactive" (their own category)
            cna_entry = {
                'assigner_id': 'unknown',  # We don't have an assigner ID for these
                'cna_name': short_name,
                'cna_org_name': org_name,
                'cna_advisory_url': advisory_url,
                'status': 'Inactive',
                'baseline_avg': 0.0,
                'current_count': 0,
                'deviation_pct': 0.0,
                'days_since_last_cve': None,  # Unknown/never
                'std_dev': None,
                'threshold_low': 0.0,
                'threshold_high': 0.0,
                'timeline_13months': timeline_13months
            }
            
            all_cnas.append(cna_entry)
            # Don't add to anomalies - they're not anomalous, just inactive
        
        # Sort anomalies by deviation magnitude (treat 999999 as highest)
        anomalies.sort(key=lambda x: abs(x['deviation_pct']) if x['deviation_pct'] < 999999 else 999999, reverse=True)
        
        # Sort all CNAs with custom logic: Growth (high to low) -> Normal -> Declining (less bad to worse) -> Inactive (at bottom)
        def sort_key(cna):
            if cna['status'] == 'Inactive':
                return -999999  # Put inactive at the very bottom
            else:
                return cna['deviation_pct']
        
        all_cnas.sort(key=sort_key, reverse=True)
        
        print(f"Identified {len(anomalies)} anomalous CNAs")
        print(f"Total CNAs analyzed: {len(all_cnas)}")
        print(f"  - Growth: {sum(1 for c in all_cnas if c['status'] == 'Growth')}")
        print(f"  - Normal: {sum(1 for c in all_cnas if c['status'] == 'Normal')}")
        print(f"  - Declining: {sum(1 for c in all_cnas if c['status'] == 'Declining')}")
        print(f"  - Inactive: {sum(1 for c in all_cnas if c['status'] == 'Inactive')}")
        
        # Prepare metadata
        metadata = {
            'generated_at': self.now.isoformat(),
            'monitoring_window_days': self.monitoring_window,
            'baseline_months': self.baseline_months,
            'monitoring_start': monitoring_start.isoformat(),
            'monitoring_end': self.now.isoformat(),
            'baseline_start': baseline_start.isoformat(),
            'baseline_end': baseline_end.isoformat(),
            'total_cnas': len(all_cnas),
            'total_anomalies': len(anomalies),
            'cnas_growth': sum(1 for c in all_cnas if c['status'] == 'Growth'),
            'cnas_normal': sum(1 for c in all_cnas if c['status'] == 'Normal'),
            'cnas_declining': sum(1 for c in all_cnas if c['status'] == 'Declining'),
            'cnas_inactive': sum(1 for c in all_cnas if c['status'] == 'Inactive')
        }
        
        return {
            'metadata': metadata,
            'cnas': all_cnas,
            'anomalies': anomalies  # Keep for backwards compatibility
        }
    
    def save_results(self, results, output_file="Web/anomaly_data.json"):
        """Save analysis results to JSON file."""
        print(f"\nSaving results to {output_file}...")
        
        # Ensure output directory exists
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        # Write JSON
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"Results saved successfully")
        print(f"Total CNAs: {results['metadata']['total_cnas']}")
        print(f"  - Growth: {results['metadata']['cnas_growth']}")
        print(f"  - Normal: {results['metadata']['cnas_normal']}")
        print(f"  - Declining: {results['metadata']['cnas_declining']}")
        print(f"  - Inactive: {results['metadata']['cnas_inactive']}")
    
    def run(self):
        """Main execution flow."""
        print("=" * 80)
        print("CNA Publishing Anomaly Analysis")
        print("=" * 80)
        
        # Step 1: Download CNA organization names
        self.load_cna_organization_names()
        
        # Step 2: Parse CVE files
        cve_data = self.parse_cve_files()
        if not cve_data:
            print("No CVE data found. Exiting.")
            return False
        
        # Step 3: Analyze activity
        results = self.analyze_cna_activity(cve_data)
        
        # Step 4: Generate report
        self.save_results(results)
        
        print("\n" + "=" * 80)
        print("Processing complete!")
        print("=" * 80)
        return True


def main():
    """Entry point for the script."""
    monitor = CVEMonitor()
    success = monitor.run()
    
    if success:
        print("\n✓ Anomaly data generated: web/anomaly_data.json")
    else:
        print("\n✗ Analysis failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
