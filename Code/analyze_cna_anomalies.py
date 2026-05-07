#!/usr/bin/env python3
"""
CNA Publishing Anomaly Analysis

Analyzes CVE publishing activity from cvelistV5 and generates anomaly data.
Outputs JSON data files to the web/ directory.

Usage:
    python code/analyze_cna_anomalies.py
"""

import json
import os
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]
    print("Warning: requests module not found. CNA organization names will not be available.")


class CVEMonitor:
    """Main class for CVE monitoring and anomaly detection."""

    def __init__(self) -> None:
        self.cves_dir: str = "cvelistV5/cves"
        self.now: datetime = datetime.now()
        self.monitoring_window: int = 30  # days
        self.baseline_months: int = 12  # months
        self.cna_org_names: dict[str, dict[str, str]] = {}  # Map CNA short names to organization names
        self.cna_by_uuid: dict[str, dict[str, str]] = {}  # Map UUID to CNA info for better matching
        self.official_cna_list: set[str] = set()  # Set of official CNA short names (no duplicates)

    def load_cna_organization_names(self) -> None:
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
                short_name = cna.get("shortName") or cna.get("ShortName") or cna.get("cnaShortName")
                org_name = cna.get("organizationName", "")
                uuid = cna.get("UUID") or cna.get("uuid")

                # Get advisory URL (try multiple locations)
                advisory_url = ""

                # Try securityAdvisories.advisories first
                sec_advisories = cna.get("securityAdvisories", {})
                if isinstance(sec_advisories, dict):
                    advisories_list = sec_advisories.get("advisories", [])
                    if advisories_list and len(advisories_list) > 0:
                        advisory_url = advisories_list[0].get("url", "")

                # Fallback to top-level advisories
                if not advisory_url:
                    advisories = cna.get("advisories", [])
                    if advisories and len(advisories) > 0:
                        advisory_url = advisories[0].get("url", "")

                cna_info = {
                    "org_name": org_name or short_name,
                    "advisory_url": advisory_url,
                    "short_name": short_name,
                    "uuid": uuid,
                }

                # Index by shortName (exact)
                if short_name:
                    self.cna_org_names[short_name] = cna_info
                    # Also index by lowercase for case-insensitive lookup
                    self.cna_org_names[short_name.lower()] = cna_info
                    # Track official CNA names (no duplicates)
                    self.official_cna_list.add(short_name)

                # Index by UUID for more reliable matching
                if uuid:
                    self.cna_by_uuid[uuid] = cna_info

            print(f"Mapped {len(self.cna_org_names)} CNA organization name entries")
            print(f"Official CNAs: {len(self.official_cna_list)}")
            print(f"Mapped {len(self.cna_by_uuid)} CNAs by UUID")

        except Exception as e:
            print(f"Warning: Could not download CNA list: {e}")
            print("Will use short names only")

    def get_cna_info(self, short_name: str | None, assigner_id: str | None) -> dict[str, str]:
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
            "org_name": short_name or "Unknown",
            "advisory_url": "",
            "short_name": short_name or "",
            "uuid": assigner_id or "",
        }

    def parse_cve_files(self) -> list[dict[str, str]]:
        """
        Recursively parse all CVE JSON files and extract required fields.
        Returns a list of dictionaries with CVE data.
        """
        print(f"Parsing CVE files from {self.cves_dir}...")
        cve_data: list[dict[str, str]] = []

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
                with open(json_file, encoding="utf-8") as f:
                    data = json.load(f)

                # Skip files where root element is a list (e.g., deltaLog.json)
                if isinstance(data, list):
                    processed += 1
                    continue

                # Extract required fields
                cve_metadata = data.get("cveMetadata", {})

                # Extract CNA name using CNAScoreCard approach
                # Use containers.cna.providerMetadata.shortName (more accurate)
                containers = data.get("containers", {})
                cna_container = containers.get("cna", {})
                provider_metadata = cna_container.get("providerMetadata", {})
                cna_short_name = provider_metadata.get("shortName")

                # Fallback to assignerShortName if providerMetadata not available
                if not cna_short_name:
                    cna_short_name = cve_metadata.get("assignerShortName", "Unknown")

                cve_entry = {
                    "cveId": cve_metadata.get("cveId", "Unknown"),
                    "datePublished": cve_metadata.get("datePublished", ""),
                    "assignerOrgId": cve_metadata.get("assignerOrgId", "Unknown"),
                    "assignerShortName": cna_short_name,
                }

                # Only add if we have a valid date
                if cve_entry["datePublished"]:
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

    def parse_date(self, date_str: str) -> datetime | None:
        """Parse ISO date string to datetime object."""
        try:
            # Handle various ISO 8601 formats
            if "T" in date_str:
                # Remove timezone info for simplicity
                date_str = date_str.split("+")[0].split("Z")[0].split(".")[0]
                return datetime.fromisoformat(date_str)
            else:
                return datetime.fromisoformat(date_str)
        except (ValueError, AttributeError):
            return None

    def calculate_seasonal_factor(self, monthly_counts: list[int]) -> float:
        """
        Calculate a seasonal adjustment factor.
        Compares the average of the same-season windows (±1 month) to the overall average.
        Returns a multiplier: <1 means this is typically a low-activity season.
        """
        if not monthly_counts or len(monthly_counts) < 6:
            return 1.0

        overall_avg = sum(monthly_counts) / len(monthly_counts)
        if overall_avg == 0:
            return 1.0

        # Current month index in Python (0=Jan, ..., 11=Dec)
        current_month = self.now.month - 1

        # Find baseline windows that correspond to the same season (±1 month)
        # Window 0 is the most recent baseline (1 month ago), window 11 is oldest (12 months ago)
        same_season_values = []
        for window_idx, count in enumerate(monthly_counts):
            # Approximate the calendar month this window corresponds to
            window_month = (current_month - 1 - window_idx) % 12
            month_distance = min(abs(window_month - current_month), 12 - abs(window_month - current_month))
            if month_distance <= 1:
                same_season_values.append(count)

        if not same_season_values:
            return 1.0

        season_avg = sum(same_season_values) / len(same_season_values)
        return season_avg / overall_avg if overall_avg > 0 else 1.0

    def generate_13month_timeline(
        self, monthly_data: dict[tuple[int, int], int], current_count: int, monitoring_window_days: int = 30
    ) -> list[dict[str, Any]]:
        """Generate 13-period timeline: 12 rolling 30-day baseline windows + current 30-day period."""
        timeline = []

        # Generate 12 rolling 30-day windows for baseline
        for i in range(12, 0, -1):
            # Calculate the end date of this 30-day window
            window_end = self.now - timedelta(days=(i * 30))
            window_start = window_end - timedelta(days=30)

            # Use month key based on the window's midpoint for grouping
            midpoint = window_start + timedelta(days=15)
            month_key = (midpoint.year, midpoint.month)

            count = monthly_data.get(month_key, 0)

            # Create clear label showing it's a 30-day window
            # Format: "Days 330-360" for readability
            days_ago_end = i * 30
            days_ago_start = days_ago_end + 30
            period_label = f"Days {days_ago_start}-{days_ago_end}"

            timeline.append({"month": period_label, "count": count, "is_current": False})

        # Add current 30-day period
        timeline.append({"month": "Last 30 Days", "count": current_count, "is_current": True})

        return timeline

    def analyze_cna_activity(self, cve_data: list[dict[str, str]]) -> dict[str, Any]:
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
        baseline_counts: dict[str, list[datetime]] = defaultdict(list)  # {assignerOrgId: [dates in baseline]}
        monitoring_counts: dict[str, int] = defaultdict(int)  # {assignerOrgId: count}
        recent_activity_counts: dict[str, int] = defaultdict(int)  # {assignerOrgId: count in last 14 days}
        last_cve_dates: dict[str, datetime] = {}  # {assignerOrgId: most recent CVE date}
        cna_names: dict[str, str] = {}  # {assignerOrgId: assignerShortName}

        # Process each CVE
        for cve in cve_data:
            date_published = self.parse_date(cve["datePublished"])
            if not date_published:
                continue

            assigner_id = cve["assignerOrgId"]
            cna_names[assigner_id] = cve["assignerShortName"]

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

        # Calculate averages for baseline using rolling 30-day windows
        cna_baselines = {}
        for assigner_id, dates in baseline_counts.items():
            if dates:
                # Calculate rolling 30-day window counts
                window_counts: dict[int, int] = defaultdict(int)
                monthly_data: dict[tuple[int, int], int] = defaultdict(int)  # For timeline compatibility

                for date_published in dates:
                    days_ago = (self.now - date_published).days

                    # Skip if in monitoring window (shouldn't happen, but be defensive)
                    if days_ago < self.monitoring_window:
                        continue

                    # Calculate which 30-day window this belongs to
                    window_idx = (days_ago - self.monitoring_window) // 30

                    # Only count if within baseline windows (0-11)
                    if 0 <= window_idx < self.baseline_months:
                        window_counts[window_idx] += 1

                        # Also maintain calendar month mapping for timeline compatibility
                        month_key = (date_published.year, date_published.month)
                        monthly_data[month_key] += 1

                # Calculate average over active windows (windows with at least one CVE)
                if window_counts:
                    avg_monthly = sum(window_counts.values()) / len(window_counts)
                    cna_baselines[assigner_id] = {
                        "avg_monthly": avg_monthly,
                        "short_name": cna_names.get(assigner_id, "Unknown"),
                        "monthly_counts": list(window_counts.values()),
                        "monthly_data": dict(monthly_data),  # Store month keys for timeline
                    }

        print(f"Found {len(cna_baselines)} CNAs with baseline data")
        print(f"Found {len(monitoring_counts)} CNAs with recent activity")

        # Find CNAs with recent activity but NO baseline (new/newly active CNAs)
        new_cnas = set(monitoring_counts.keys()) - set(cna_baselines.keys())
        print(f"Found {len(new_cnas)} new/newly active CNAs (no baseline data)")

        # Find ALL official CNAs that we haven't seen yet (completely inactive)
        all_seen_cna_ids = set(cna_baselines.keys()) | set(monitoring_counts.keys())
        official_cna_names = self.official_cna_list  # Use official list without duplicates

        # Map official names to IDs we've seen
        seen_cna_names = set()
        for cna_id in all_seen_cna_ids:
            name = cna_names.get(cna_id, "Unknown")
            if name != "Unknown":
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
            baseline_avg: float = baseline_info["avg_monthly"]  # type: ignore[assignment]
            baseline_monthly_counts: list[int] = baseline_info["monthly_counts"]  # type: ignore[assignment]

            # Calculate standard deviation if we have enough data
            if len(baseline_monthly_counts) >= 3:
                try:
                    std_dev = statistics.stdev(baseline_monthly_counts)
                except statistics.StatisticsError:
                    std_dev = 0
            else:
                std_dev = 0

            # Status thresholds
            # Normal = within 50% to 250% of baseline (-50% to +150% growth)
            # Declining = below 50% of baseline (below -50% from baseline)
            # Growth = above 250% of baseline (above +150% growth)
            threshold_low = baseline_avg * 0.5  # Below 50% of baseline is Declining
            threshold_high = baseline_avg * 2.5  # Above 250% of baseline is Growth

            # Apply seasonal normalization
            seasonal_factor = self.calculate_seasonal_factor(baseline_monthly_counts)
            # Adjust thresholds - if this is typically a low season, lower the bar
            adjusted_threshold_low = threshold_low * seasonal_factor
            adjusted_threshold_high = threshold_high * seasonal_factor

            # Identify status type based on deviation from baseline
            anomaly_type = None

            # Growth: Above 250% of baseline (+150% growth)
            if current_count > adjusted_threshold_high:
                anomaly_type = "Growth"

            # Declining: Below 50% of baseline (-50% from baseline)
            # Only flag if baseline was meaningful (>=0.5 CVEs/month)
            elif current_count < adjusted_threshold_low and baseline_avg >= 0.5:
                anomaly_type = "Declining"

            # Otherwise: Normal (within 50% to 250% of baseline)

            # Determine status for all CNAs
            if anomaly_type:
                status = anomaly_type  # "Growth" or "Declining"
            else:
                status = "Normal"

            deviation_pct = ((current_count - baseline_avg) / baseline_avg * 100) if baseline_avg > 0 else 0

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
            short_name: str = baseline_info["short_name"]  # type: ignore[assignment]
            cna_info = self.get_cna_info(short_name, assigner_id)
            org_name = cna_info.get("org_name", "")
            advisory_url = cna_info.get("advisory_url", "")

            # Generate 13-month timeline for detail page
            cna_monthly_data: dict[tuple[int, int], int] = baseline_info.get("monthly_data", {})  # type: ignore[assignment]
            timeline_13months = self.generate_13month_timeline(cna_monthly_data, current_count)

            cna_entry = {
                "assigner_id": assigner_id,
                "cna_name": short_name,
                "cna_org_name": org_name,
                "cna_advisory_url": advisory_url,
                "status": status,
                "baseline_avg": round(baseline_avg, 2),
                "current_count": current_count,
                "deviation_pct": round(deviation_pct, 1),
                "days_since_last_cve": days_since_last,
                "std_dev": round(std_dev, 2) if std_dev > 0 else None,
                "threshold_low": round(threshold_low, 2),
                "threshold_high": round(threshold_high, 2),
                "timeline_13months": timeline_13months,
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
            short_name = cna_names.get(assigner_id, "Unknown")
            cna_info = self.get_cna_info(short_name, assigner_id)
            org_name = cna_info.get("org_name", "")
            advisory_url = cna_info.get("advisory_url", "")

            # Generate 13-month timeline for new CNAs (all zeros + current)
            timeline_13months = self.generate_13month_timeline({}, current_count)

            # New CNAs are marked as "Growth" (went from 0 to something)
            cna_entry = {
                "assigner_id": assigner_id,
                "cna_name": short_name,
                "cna_org_name": org_name,
                "cna_advisory_url": advisory_url,
                "status": "Growth",
                "baseline_avg": 0.0,
                "current_count": current_count,
                "deviation_pct": 999999.0,  # Large number to represent infinite growth from 0
                "days_since_last_cve": days_since_last,
                "std_dev": None,
                "threshold_low": 0.0,
                "threshold_high": 0.0,
                "timeline_13months": timeline_13months,
            }

            all_cnas.append(cna_entry)
            anomalies.append(cna_entry)  # New CNAs are anomalies

        # Process completely inactive CNAs (in official list but no CVEs in dataset)
        for short_name in inactive_cna_names:
            cna_info = self.get_cna_info(short_name, None)
            org_name = cna_info.get("org_name", short_name)
            advisory_url = cna_info.get("advisory_url", "")

            # Generate 13-month timeline for inactive CNAs (all zeros)
            timeline_13months = self.generate_13month_timeline({}, 0)

            # Completely inactive CNAs - marked as "Inactive" (their own category)
            cna_entry = {
                "assigner_id": "unknown",  # We don't have an assigner ID for these
                "cna_name": short_name,
                "cna_org_name": org_name,
                "cna_advisory_url": advisory_url,
                "status": "Inactive",
                "baseline_avg": 0.0,
                "current_count": 0,
                "deviation_pct": 0.0,
                "days_since_last_cve": None,  # Unknown/never
                "std_dev": None,
                "threshold_low": 0.0,
                "threshold_high": 0.0,
                "timeline_13months": timeline_13months,
            }

            all_cnas.append(cna_entry)
            # Don't add to anomalies - they're not anomalous, just inactive

        # Sort anomalies by deviation magnitude (treat 999999 as highest)
        def anomaly_sort_key(x: dict[str, Any]) -> float:
            dev = float(x["deviation_pct"])
            return abs(dev) if dev < 999999 else 999999.0

        anomalies.sort(key=anomaly_sort_key, reverse=True)

        # Sort all CNAs: Growth (high to low) -> Normal -> Declining -> Inactive (bottom)
        def sort_key(cna: dict[str, Any]) -> float:
            if cna["status"] == "Inactive":
                return -999999.0  # Put inactive at the very bottom
            else:
                return float(cna["deviation_pct"])

        all_cnas.sort(key=sort_key, reverse=True)

        print(f"Identified {len(anomalies)} anomalous CNAs")
        print(f"Total CNAs analyzed: {len(all_cnas)}")
        print(f"  - Growth: {sum(1 for c in all_cnas if c['status'] == 'Growth')}")
        print(f"  - Normal: {sum(1 for c in all_cnas if c['status'] == 'Normal')}")
        print(f"  - Declining: {sum(1 for c in all_cnas if c['status'] == 'Declining')}")
        print(f"  - Inactive: {sum(1 for c in all_cnas if c['status'] == 'Inactive')}")

        # Prepare metadata
        metadata = {
            "generated_at": self.now.isoformat(),
            "monitoring_window_days": self.monitoring_window,
            "baseline_months": self.baseline_months,
            "monitoring_start": monitoring_start.isoformat(),
            "monitoring_end": self.now.isoformat(),
            "baseline_start": baseline_start.isoformat(),
            "baseline_end": baseline_end.isoformat(),
            "total_cnas": len(all_cnas),
            "total_anomalies": len(anomalies),
            "cnas_growth": sum(1 for c in all_cnas if c["status"] == "Growth"),
            "cnas_normal": sum(1 for c in all_cnas if c["status"] == "Normal"),
            "cnas_declining": sum(1 for c in all_cnas if c["status"] == "Declining"),
            "cnas_inactive": sum(1 for c in all_cnas if c["status"] == "Inactive"),
        }

        return {
            "metadata": metadata,
            "cnas": all_cnas,
            "anomalies": anomalies,  # Keep for backwards compatibility
        }

    def save_results(self, results: dict[str, Any], output_file: str = "Web/anomaly_data.json") -> None:
        """Save analysis results to JSON file."""
        print(f"\nSaving results to {output_file}...")

        # Ensure output directory exists
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Write JSON
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print("Results saved successfully")
        print(f"Total CNAs: {results['metadata']['total_cnas']}")
        print(f"  - Growth: {results['metadata']['cnas_growth']}")
        print(f"  - Normal: {results['metadata']['cnas_normal']}")
        print(f"  - Declining: {results['metadata']['cnas_declining']}")
        print(f"  - Inactive: {results['metadata']['cnas_inactive']}")

    def run(self) -> bool:
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


def main() -> None:
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
