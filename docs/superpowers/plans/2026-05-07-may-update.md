# CNAPulse May Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Comprehensive quality, performance, and feature update to the CNAPulse CNA monitoring dashboard.

**Architecture:** The project remains a static GitHub Pages site with a Python analysis script run via GitHub Actions CI. Improvements are grouped into 5 phases: (1) tooling/project setup, (2) Python analysis improvements, (3) CI/CD improvements, (4) frontend improvements, (5) polish and testing. Each phase produces independently deployable work.

**Tech Stack:** Python 3.11+, pytest, ruff, mypy, Tailwind CSS (built), Chart.js 4.4.0, GitHub Actions, GitHub Pages

---

## Phase 1: Project Tooling & Setup

### Task 1: Migrate to pyproject.toml

**Files:**

- Create: `pyproject.toml`
- Delete: `requirements.txt`
- Modify: `.github/workflows/deploy.yml`

- [ ] **Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta"

[project]
name = "cnapulse"
version = "2.0.0"
description = "Monitoring CVE Numbering Authority publishing activity and trends"
requires-python = ">=3.11"
license = {text = "MIT"}
dependencies = [
    "requests>=2.31.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-cov>=4.1.0",
    "pytest-mock>=3.11.0",
    "ruff>=0.4.0",
    "mypy>=1.10.0",
    "types-requests>=2.31.0",
]

[project.scripts]
cnapulse = "Code.analyze_cna_anomalies:main"

[tool.ruff]
target-version = "py311"
line-length = 120

[tool.ruff.lint]
select = ["E", "F", "I", "N", "W", "UP"]

[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["."]
```

- [ ] **Step 2: Delete requirements.txt**

```bash
rm requirements.txt
```

- [ ] **Step 3: Update deploy.yml to use pyproject.toml**

In `.github/workflows/deploy.yml`, change the install step from:

```yaml
- name: Install dependencies
  run: |
    python -m pip install --upgrade pip
    pip install requests
```

to:

```yaml
- name: Install dependencies
  run: |
    python -m pip install --upgrade pip
    pip install -e .
```

- [ ] **Step 4: Test local install**

Run: `pip install -e ".[dev]"`
Expected: Installs successfully with all dev dependencies

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml .github/workflows/deploy.yml
git rm requirements.txt
git commit -m "build: migrate from requirements.txt to pyproject.toml"
```

---

### Task 2: Add ruff and mypy configuration

**Files:**

- Modify: `Code/analyze_cna_anomalies.py` (fix lint issues)
- Create: `Code/__init__.py`

- [ ] **Step 1: Create package init**

```python
# Code/__init__.py
```

(empty file to make Code a package)

- [ ] **Step 2: Run ruff and fix issues**

Run: `ruff check Code/ --fix`
Expected: Auto-fixes import ordering and style issues

- [ ] **Step 3: Run ruff format**

Run: `ruff format Code/`
Expected: Formats code to consistent style

- [ ] **Step 4: Add type annotations to analyze_cna_anomalies.py**

Add type hints to key methods. The main changes:

```python
from typing import Any

class CVEMonitor:
    def __init__(self) -> None:
        self.cves_dir: str = 'cvelistV5/cves'
        self.now: datetime = datetime.now()
        self.monitoring_window: int = 30
        self.baseline_months: int = 12
        self.cna_org_names: dict[str, dict[str, str]] = {}
        self.cna_by_uuid: dict[str, dict[str, str]] = {}
        self.official_cna_list: set[str] = set()

    def load_cna_organization_names(self) -> None: ...
    def get_cna_info(self, short_name: str | None, assigner_id: str | None) -> dict[str, str]: ...
    def parse_cve_files(self) -> list[dict[str, str]]: ...
    def parse_date(self, date_str: str) -> datetime | None: ...
    def generate_13month_timeline(self, monthly_data: dict[tuple[int, int], int], current_count: int, monitoring_window_days: int = 30) -> list[dict[str, Any]]: ...
    def analyze_cna_activity(self, cve_data: list[dict[str, str]]) -> dict[str, Any]: ...
    def save_results(self, results: dict[str, Any], output_file: str = "Web/anomaly_data.json") -> None: ...
    def run(self) -> bool: ...
```

- [ ] **Step 5: Run mypy**

Run: `mypy Code/ --ignore-missing-imports`
Expected: Passes (or minimal errors to fix)

- [ ] **Step 6: Commit**

```bash
git add Code/ pyproject.toml
git commit -m "build: add ruff linting and mypy type checking"
```

---

### Task 3: Add test infrastructure

**Files:**

- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Create: `tests/test_analyze_cna_anomalies.py`

- [ ] **Step 1: Create test directory and conftest**

```python
# tests/__init__.py
```

```python
# tests/conftest.py
import pytest
from datetime import datetime
from Code.analyze_cna_anomalies import CVEMonitor


@pytest.fixture
def monitor():
    """Create a CVEMonitor instance with a fixed 'now' time for reproducibility."""
    m = CVEMonitor()
    m.now = datetime(2026, 5, 7, 12, 0, 0)
    return m


@pytest.fixture
def sample_cve_data():
    """Minimal CVE dataset for testing analysis logic."""
    return [
        {
            "cveId": "CVE-2026-0001",
            "datePublished": "2026-04-15T10:00:00",
            "assignerOrgId": "uuid-active-cna",
            "assignerShortName": "ActiveCNA",
        },
        {
            "cveId": "CVE-2026-0002",
            "datePublished": "2026-04-20T10:00:00",
            "assignerOrgId": "uuid-active-cna",
            "assignerShortName": "ActiveCNA",
        },
        {
            "cveId": "CVE-2026-0003",
            "datePublished": "2026-04-25T10:00:00",
            "assignerOrgId": "uuid-active-cna",
            "assignerShortName": "ActiveCNA",
        },
        # Baseline data for ActiveCNA (spread across past 12 months)
        {
            "cveId": "CVE-2025-1001",
            "datePublished": "2025-06-15T10:00:00",
            "assignerOrgId": "uuid-active-cna",
            "assignerShortName": "ActiveCNA",
        },
        {
            "cveId": "CVE-2025-1002",
            "datePublished": "2025-07-15T10:00:00",
            "assignerOrgId": "uuid-active-cna",
            "assignerShortName": "ActiveCNA",
        },
        {
            "cveId": "CVE-2025-1003",
            "datePublished": "2025-08-15T10:00:00",
            "assignerOrgId": "uuid-active-cna",
            "assignerShortName": "ActiveCNA",
        },
        {
            "cveId": "CVE-2025-1004",
            "datePublished": "2025-09-15T10:00:00",
            "assignerOrgId": "uuid-active-cna",
            "assignerShortName": "ActiveCNA",
        },
        {
            "cveId": "CVE-2025-1005",
            "datePublished": "2025-10-15T10:00:00",
            "assignerOrgId": "uuid-active-cna",
            "assignerShortName": "ActiveCNA",
        },
        {
            "cveId": "CVE-2025-1006",
            "datePublished": "2025-11-15T10:00:00",
            "assignerOrgId": "uuid-active-cna",
            "assignerShortName": "ActiveCNA",
        },
        # A new CNA with only recent activity
        {
            "cveId": "CVE-2026-9001",
            "datePublished": "2026-04-28T10:00:00",
            "assignerOrgId": "uuid-new-cna",
            "assignerShortName": "NewCNA",
        },
    ]
```

- [ ] **Step 2: Write tests for parse_date**

```python
# tests/test_analyze_cna_anomalies.py
from datetime import datetime
from Code.analyze_cna_anomalies import CVEMonitor


class TestParseDate:
    def test_iso_with_timezone(self, monitor):
        result = monitor.parse_date("2026-01-15T10:30:00+00:00")
        assert result == datetime(2026, 1, 15, 10, 30, 0)

    def test_iso_with_z(self, monitor):
        result = monitor.parse_date("2026-01-15T10:30:00Z")
        assert result == datetime(2026, 1, 15, 10, 30, 0)

    def test_iso_with_milliseconds(self, monitor):
        result = monitor.parse_date("2026-01-15T10:30:00.123456")
        assert result == datetime(2026, 1, 15, 10, 30, 0)

    def test_date_only(self, monitor):
        result = monitor.parse_date("2026-01-15")
        assert result == datetime(2026, 1, 15, 0, 0, 0)

    def test_invalid_date(self, monitor):
        result = monitor.parse_date("not-a-date")
        assert result is None

    def test_empty_string(self, monitor):
        result = monitor.parse_date("")
        assert result is None
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `pytest tests/test_analyze_cna_anomalies.py -v`
Expected: All 6 tests pass

- [ ] **Step 4: Write tests for analyze_cna_activity**

Append to `tests/test_analyze_cna_anomalies.py`:

```python
class TestAnalyzeCNAActivity:
    def test_identifies_active_cna(self, monitor, sample_cve_data):
        results = monitor.analyze_cna_activity(sample_cve_data)
        cnas = results["cnas"]
        active = next((c for c in cnas if c["cna_name"] == "ActiveCNA"), None)
        assert active is not None
        assert active["current_count"] == 3

    def test_identifies_new_cna(self, monitor, sample_cve_data):
        results = monitor.analyze_cna_activity(sample_cve_data)
        cnas = results["cnas"]
        new = next((c for c in cnas if c["cna_name"] == "NewCNA"), None)
        assert new is not None
        assert new["status"] == "Growth"
        assert new["deviation_pct"] == 999999.0

    def test_metadata_counts(self, monitor, sample_cve_data):
        results = monitor.analyze_cna_activity(sample_cve_data)
        metadata = results["metadata"]
        assert metadata["total_cnas"] >= 2
        assert "cnas_growth" in metadata
        assert "cnas_normal" in metadata
        assert "cnas_declining" in metadata
        assert "cnas_inactive" in metadata

    def test_baseline_calculation(self, monitor, sample_cve_data):
        results = monitor.analyze_cna_activity(sample_cve_data)
        cnas = results["cnas"]
        active = next((c for c in cnas if c["cna_name"] == "ActiveCNA"), None)
        assert active is not None
        # 6 CVEs across ~6 months in baseline = avg ~1 per month
        assert active["baseline_avg"] > 0
        assert active["baseline_avg"] <= 6.0

    def test_days_since_last_cve(self, monitor, sample_cve_data):
        results = monitor.analyze_cna_activity(sample_cve_data)
        cnas = results["cnas"]
        active = next((c for c in cnas if c["cna_name"] == "ActiveCNA"), None)
        assert active is not None
        # Last CVE was April 25, now is May 7 = 12 days
        assert active["days_since_last_cve"] == 12

    def test_timeline_has_13_entries(self, monitor, sample_cve_data):
        results = monitor.analyze_cna_activity(sample_cve_data)
        cnas = results["cnas"]
        active = next((c for c in cnas if c["cna_name"] == "ActiveCNA"), None)
        assert active is not None
        assert len(active["timeline_13months"]) == 13
        assert active["timeline_13months"][-1]["is_current"] is True


class TestGenerateTimeline:
    def test_empty_monthly_data(self, monitor):
        timeline = monitor.generate_13month_timeline({}, 5)
        assert len(timeline) == 13
        assert timeline[-1]["count"] == 5
        assert timeline[-1]["is_current"] is True
        # All baseline periods should be 0
        for entry in timeline[:-1]:
            assert entry["count"] == 0

    def test_with_monthly_data(self, monitor):
        monthly_data = {(2025, 6): 3, (2025, 7): 5}
        timeline = monitor.generate_13month_timeline(monthly_data, 2)
        assert len(timeline) == 13
        assert timeline[-1]["count"] == 2


class TestGetCNAInfo:
    def test_exact_match(self, monitor):
        monitor.cna_org_names["TestCNA"] = {
            "org_name": "Test Organization",
            "advisory_url": "https://example.com",
            "short_name": "TestCNA",
            "uuid": "test-uuid",
        }
        result = monitor.get_cna_info("TestCNA", "some-id")
        assert result["org_name"] == "Test Organization"

    def test_case_insensitive_match(self, monitor):
        monitor.cna_org_names["testcna"] = {
            "org_name": "Test Organization",
            "advisory_url": "https://example.com",
            "short_name": "TestCNA",
            "uuid": "test-uuid",
        }
        result = monitor.get_cna_info("TestCNA", "some-id")
        assert result["org_name"] == "Test Organization"

    def test_uuid_fallback(self, monitor):
        monitor.cna_by_uuid["test-uuid"] = {
            "org_name": "UUID Org",
            "advisory_url": "",
            "short_name": "UUIDOrg",
            "uuid": "test-uuid",
        }
        result = monitor.get_cna_info("NonExistent", "test-uuid")
        assert result["org_name"] == "UUID Org"

    def test_no_match_returns_default(self, monitor):
        result = monitor.get_cna_info("Unknown", "no-match")
        assert result["org_name"] == "Unknown"
```

- [ ] **Step 5: Run all tests**

Run: `pytest tests/ -v`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add tests/
git commit -m "test: add unit tests for CNA analysis logic"
```

---

## Phase 2: Python Analysis Improvements

### Task 4: Better baseline calculation with true rolling 30-day windows

**Files:**

- Modify: `Code/analyze_cna_anomalies.py`
- Modify: `tests/test_analyze_cna_anomalies.py`

- [ ] **Step 1: Write failing test for rolling window baseline**

Append to `tests/test_analyze_cna_anomalies.py`:

```python
class TestRollingWindowBaseline:
    def test_baseline_uses_rolling_windows(self, monitor):
        """Baseline should use 12 rolling 30-day windows, not calendar months."""
        # Create data with known distribution across rolling windows
        cve_data = []
        # 2 CVEs per 30-day window for 6 windows in baseline
        for i in range(6):
            days_ago = 60 + (i * 30)  # starts at day 60 back into baseline
            for j in range(2):
                cve_data.append({
                    "cveId": f"CVE-2025-{i}{j}",
                    "datePublished": (monitor.now - timedelta(days=days_ago + j)).isoformat(),
                    "assignerOrgId": "uuid-test",
                    "assignerShortName": "TestCNA",
                })
        # 5 CVEs in the current monitoring window
        for i in range(5):
            cve_data.append({
                "cveId": f"CVE-2026-{i}",
                "datePublished": (monitor.now - timedelta(days=i + 1)).isoformat(),
                "assignerOrgId": "uuid-test",
                "assignerShortName": "TestCNA",
            })

        results = monitor.analyze_cna_activity(cve_data)
        cna = next(c for c in results["cnas"] if c["cna_name"] == "TestCNA")
        # Baseline avg should be 2.0 (2 CVEs per 30-day window)
        assert 1.5 <= cna["baseline_avg"] <= 2.5
```

- [ ] **Step 2: Run test to verify it fails or passes with current logic**

Run: `pytest tests/test_analyze_cna_anomalies.py::TestRollingWindowBaseline -v`

- [ ] **Step 3: Refactor baseline calculation to use true rolling 30-day windows**

Replace the baseline counting logic in `analyze_cna_activity`:

```python
# Replace the baseline_counts defaultdict(list) approach with rolling windows
# In analyze_cna_activity, after processing each CVE, calculate baselines:

# Calculate rolling 30-day window baselines
rolling_window_counts = defaultdict(lambda: defaultdict(int))  # {assigner_id: {window_idx: count}}

for cve in cve_data:
    date_published = self.parse_date(cve['datePublished'])
    if not date_published:
        continue

    assigner_id = cve['assignerOrgId']

    # Determine which rolling window this falls into
    days_ago = (self.now - date_published).days
    if days_ago < self.monitoring_window:
        continue  # In monitoring window, not baseline

    # Window index: 0 = most recent baseline window, 11 = oldest
    window_idx = (days_ago - self.monitoring_window) // 30
    if 0 <= window_idx < self.baseline_months:
        rolling_window_counts[assigner_id][window_idx] += 1

# Calculate averages from rolling windows
cna_baselines = {}
for assigner_id, windows in rolling_window_counts.items():
    if windows:
        window_values = [windows.get(i, 0) for i in range(self.baseline_months)]
        # Only count windows that are non-zero for average (or all 12)
        non_zero_windows = [v for v in window_values if v > 0]
        if non_zero_windows:
            avg_monthly = sum(window_values) / len(non_zero_windows)
        else:
            avg_monthly = 0

        cna_baselines[assigner_id] = {
            'avg_monthly': avg_monthly,
            'short_name': cna_names.get(assigner_id, 'Unknown'),
            'monthly_counts': window_values,
            'monthly_data': {i: windows.get(i, 0) for i in range(self.baseline_months)}
        }
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/ -v`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add Code/analyze_cna_anomalies.py tests/
git commit -m "feat: use true rolling 30-day windows for baseline calculation"
```

---

### Task 5: Seasonal normalization

**Files:**

- Modify: `Code/analyze_cna_anomalies.py`
- Modify: `tests/test_analyze_cna_anomalies.py`

- [ ] **Step 1: Write failing test**

```python
class TestSeasonalNormalization:
    def test_seasonal_factor_applied(self, monitor):
        """CNAs with cyclical patterns should not be falsely flagged."""
        cve_data = []
        # CNA with high activity in Q1 (Jan-Mar) and low in Q2 (Apr-Jun)
        # Baseline: 10 CVEs in Jan, Feb, Mar; 1 in Apr, May, Jun, Jul, Aug, Sep, Oct, Nov
        for month in range(1, 12):
            count = 10 if month <= 3 else 1
            days_back = 30 + ((11 - month) * 30)  # spread across baseline
            for i in range(count):
                cve_data.append({
                    "cveId": f"CVE-2025-{month:02d}{i:02d}",
                    "datePublished": (monitor.now - timedelta(days=days_back + i)).isoformat(),
                    "assignerOrgId": "uuid-seasonal",
                    "assignerShortName": "SeasonalCNA",
                })
        # Current window (late April/May) has 1 CVE - matches low season
        cve_data.append({
            "cveId": "CVE-2026-0001",
            "datePublished": (monitor.now - timedelta(days=5)).isoformat(),
            "assignerOrgId": "uuid-seasonal",
            "assignerShortName": "SeasonalCNA",
        })

        results = monitor.analyze_cna_activity(cve_data)
        cna = next(c for c in results["cnas"] if c["cna_name"] == "SeasonalCNA")
        # Should not be marked as Declining because this matches seasonal pattern
        assert cna["status"] in ("Normal", "Growth")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_analyze_cna_anomalies.py::TestSeasonalNormalization -v`
Expected: FAIL (currently would be Declining)

- [ ] **Step 3: Implement seasonal normalization**

Add a method to CVEMonitor:

```python
def calculate_seasonal_factor(self, monthly_counts: list[int]) -> float:
    """
    Calculate a seasonal adjustment factor.
    Compares the average of the same-season windows (±1 month) to the overall average.
    Returns a multiplier: >1 means this is typically a high-activity season.
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
        month_distance = min(
            abs(window_month - current_month),
            12 - abs(window_month - current_month)
        )
        if month_distance <= 1:
            same_season_values.append(count)

    if not same_season_values:
        return 1.0

    season_avg = sum(same_season_values) / len(same_season_values)
    return season_avg / overall_avg if overall_avg > 0 else 1.0
```

Then in `analyze_cna_activity`, adjust the threshold comparison:

```python
# After calculating threshold_low and threshold_high:
seasonal_factor = self.calculate_seasonal_factor(monthly_counts)
adjusted_threshold_low = threshold_low * seasonal_factor
adjusted_threshold_high = threshold_high * seasonal_factor

# Use adjusted thresholds for status determination
if current_count > adjusted_threshold_high:
    anomaly_type = "Growth"
elif current_count < adjusted_threshold_low and avg_monthly >= 0.5:
    anomaly_type = "Declining"
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/ -v`
Expected: All tests pass including the new seasonal test

- [ ] **Step 5: Commit**

```bash
git add Code/analyze_cna_anomalies.py tests/
git commit -m "feat: add seasonal normalization to reduce false anomaly flags"
```

---

### Task 6: CNA metadata enrichment

**Files:**

- Modify: `Code/analyze_cna_anomalies.py`
- Modify: `tests/test_analyze_cna_anomalies.py`

- [ ] **Step 1: Write test for enriched metadata**

```python
class TestCNAMetadataEnrichment:
    def test_country_extracted(self, monitor):
        """CNA entries should include country if available from official list."""
        monitor.cna_org_names["TestCNA"] = {
            "org_name": "Test Corp",
            "advisory_url": "https://example.com",
            "short_name": "TestCNA",
            "uuid": "test-uuid",
            "country": "US",
            "scope_type": "product",
        }
        result = monitor.get_cna_info("TestCNA", "test-uuid")
        assert result.get("country") == "US"

    def test_scope_type_extracted(self, monitor):
        """CNA entries should include scope type if available."""
        monitor.cna_org_names["TestCNA"] = {
            "org_name": "Test Corp",
            "advisory_url": "https://example.com",
            "short_name": "TestCNA",
            "uuid": "test-uuid",
            "country": "DE",
            "scope_type": "product",
        }
        result = monitor.get_cna_info("TestCNA", "test-uuid")
        assert result.get("scope_type") == "product"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_analyze_cna_anomalies.py::TestCNAMetadataEnrichment -v`
Expected: FAIL (country/scope_type not in data)

- [ ] **Step 3: Enrich load_cna_organization_names to extract additional fields**

In `load_cna_organization_names`, extend `cna_info`:

```python
cna_info = {
    'org_name': org_name or short_name,
    'advisory_url': advisory_url,
    'short_name': short_name,
    'uuid': uuid,
    'country': cna.get('country', {}).get('code', '') if isinstance(cna.get('country'), dict) else cna.get('country', ''),
    'scope_type': cna.get('scope', {}).get('type', '') if isinstance(cna.get('scope'), dict) else '',
}
```

- [ ] **Step 4: Include enriched fields in CNA output entries**

In `analyze_cna_activity`, when building `cna_entry`:

```python
cna_entry = {
    # ... existing fields ...
    'country': cna_info.get('country', ''),
    'scope_type': cna_info.get('scope_type', ''),
}
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/ -v`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add Code/analyze_cna_anomalies.py tests/
git commit -m "feat: enrich CNA data with country and scope type metadata"
```

---

### Task 7: Historical data retention

**Files:**

- Modify: `Code/analyze_cna_anomalies.py`
- Modify: `.github/workflows/deploy.yml`
- Create: `Web/history/` (directory, populated by CI)

- [ ] **Step 1: Add history generation to CVEMonitor**

Add method to `CVEMonitor`:

```python
def save_daily_snapshot(self, results: dict[str, Any]) -> None:
    """Save a daily snapshot with just summary stats (not full CNA data)."""
    today = self.now.strftime("%Y-%m-%d")
    history_dir = Path("Web/history")
    history_dir.mkdir(parents=True, exist_ok=True)

    snapshot = {
        "date": today,
        "generated_at": results["metadata"]["generated_at"],
        "total_cnas": results["metadata"]["total_cnas"],
        "cnas_growth": results["metadata"]["cnas_growth"],
        "cnas_normal": results["metadata"]["cnas_normal"],
        "cnas_declining": results["metadata"]["cnas_declining"],
        "cnas_inactive": results["metadata"]["cnas_inactive"],
        "top_growth": [
            {"cna_name": c["cna_name"], "current_count": c["current_count"], "deviation_pct": c["deviation_pct"]}
            for c in results["cnas"] if c["status"] == "Growth"
        ][:10],
        "top_declining": [
            {"cna_name": c["cna_name"], "current_count": c["current_count"], "deviation_pct": c["deviation_pct"]}
            for c in results["cnas"] if c["status"] == "Declining"
        ][:10],
    }

    snapshot_file = history_dir / f"{today}.json"
    with open(snapshot_file, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2)

    # Update history index
    self._update_history_index(history_dir)

def _update_history_index(self, history_dir: Path) -> None:
    """Maintain a history index file listing all available snapshots."""
    snapshots = sorted(history_dir.glob("2*.json"), reverse=True)
    index = [s.stem for s in snapshots]  # List of date strings

    index_file = history_dir / "index.json"
    with open(index_file, "w", encoding="utf-8") as f:
        json.dump({"snapshots": index}, f, indent=2)
```

- [ ] **Step 2: Call save_daily_snapshot in run()**

After `self.save_results(results)`:

```python
# Step 5: Save daily snapshot for historical tracking
self.save_daily_snapshot(results)
```

- [ ] **Step 3: Update deploy.yml to commit history files**

Change the git add line:

```yaml
git add Web/anomaly_data.json Web/history/
```

- [ ] **Step 4: Write test**

```python
class TestHistoricalSnapshots:
    def test_save_daily_snapshot(self, monitor, sample_cve_data, tmp_path):
        """Daily snapshot should contain summary stats."""
        import os
        os.chdir(tmp_path)
        (tmp_path / "Web").mkdir()

        results = monitor.analyze_cna_activity(sample_cve_data)
        monitor.save_daily_snapshot(results)

        history_dir = tmp_path / "Web" / "history"
        assert history_dir.exists()

        snapshot_file = history_dir / "2026-05-07.json"
        assert snapshot_file.exists()

        import json
        snapshot = json.loads(snapshot_file.read_text())
        assert "date" in snapshot
        assert "total_cnas" in snapshot
        assert "top_growth" in snapshot
        assert "top_declining" in snapshot

    def test_history_index_created(self, monitor, sample_cve_data, tmp_path):
        """History index should list available snapshots."""
        import os
        os.chdir(tmp_path)
        (tmp_path / "Web").mkdir()

        results = monitor.analyze_cna_activity(sample_cve_data)
        monitor.save_daily_snapshot(results)

        index_file = tmp_path / "Web" / "history" / "index.json"
        assert index_file.exists()

        import json
        index = json.loads(index_file.read_text())
        assert "2026-05-07" in index["snapshots"]
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/ -v`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add Code/analyze_cna_anomalies.py tests/ .github/workflows/deploy.yml
git commit -m "feat: add daily historical snapshots for trend analysis"
```

---

### Task 8: Split data files (summary + per-CNA detail files)

**Files:**

- Modify: `Code/analyze_cna_anomalies.py`
- Modify: `Web/script.js`
- Modify: `Web/cna-detail.js`
- Modify: `.github/workflows/deploy.yml`

- [ ] **Step 1: Add split output to save_results**

Add method to `CVEMonitor`:

```python
def save_split_results(self, results: dict[str, Any]) -> None:
    """Save results split into summary + per-CNA detail files."""
    # Summary file (no timeline data - lightweight for main page)
    summary = {
        "metadata": results["metadata"],
        "cnas": [
            {
                "assigner_id": c["assigner_id"],
                "cna_name": c["cna_name"],
                "cna_org_name": c["cna_org_name"],
                "cna_advisory_url": c["cna_advisory_url"],
                "status": c["status"],
                "baseline_avg": c["baseline_avg"],
                "current_count": c["current_count"],
                "deviation_pct": c["deviation_pct"],
                "days_since_last_cve": c["days_since_last_cve"],
                "country": c.get("country", ""),
                "scope_type": c.get("scope_type", ""),
            }
            for c in results["cnas"]
        ],
    }

    summary_file = "Web/summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    # Per-CNA detail files (with timeline)
    detail_dir = Path("Web/cna")
    detail_dir.mkdir(parents=True, exist_ok=True)

    for cna in results["cnas"]:
        cna_file = detail_dir / f"{cna['cna_name']}.json"
        with open(cna_file, "w", encoding="utf-8") as f:
            json.dump(cna, f, indent=2, ensure_ascii=False)

    print(f"Summary saved: {summary_file}")
    print(f"CNA details saved: {len(results['cnas'])} files in Web/cna/")
```

- [ ] **Step 2: Call save_split_results in run()**

After `self.save_results(results)`:

```python
self.save_split_results(results)
```

- [ ] **Step 3: Update script.js to load from summary.json with fallback**

Replace the fetch in `loadAnomalyData()`:

```javascript
async function loadAnomalyData() {
  try {
    // Try summary.json first (lighter payload), fall back to anomaly_data.json
    let response = await fetch("summary.json");
    if (!response.ok) {
      response = await fetch("anomaly_data.json");
    }
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    allCNAs = data.cnas || [];
    filteredCNAs = [...allCNAs];
    updateMetadata(data.metadata);
    updateMetrics(data.metadata);
    updateCNATable(filteredCNAs);
  } catch (error) {
    console.error("Error fetching anomaly data:", error);
    showError("Could not load anomaly data. The data file may not exist yet.");
  }
}
```

- [ ] **Step 4: Update cna-detail.js to load from per-CNA file with fallback**

Replace the fetch in `loadCNADetail()`:

```javascript
async function loadCNADetail() {
  const cnaName = getCNAFromURL();

  if (!cnaName) {
    showError("No CNA specified in URL");
    return;
  }

  try {
    // Try per-CNA detail file first, fall back to full data
    let cna = null;

    const detailResponse = await fetch(
      `cna/${encodeURIComponent(cnaName)}.json`,
    );
    if (detailResponse.ok) {
      cna = await detailResponse.json();
    } else {
      // Fallback to anomaly_data.json
      const response = await fetch("anomaly_data.json");
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      cna = data.cnas.find((c) => c.cna_name === cnaName);
    }

    if (!cna) {
      showError(`CNA "${cnaName}" not found in dataset`);
      return;
    }

    displayCNA(cna);
  } catch (error) {
    console.error("Error loading CNA data:", error);
    showError("Failed to load CNA data. Please try again later.");
  }
}
```

- [ ] **Step 5: Update deploy.yml git add**

```yaml
git add Web/anomaly_data.json Web/summary.json Web/cna/ Web/history/
```

- [ ] **Step 6: Commit**

```bash
git add Code/analyze_cna_anomalies.py Web/script.js Web/cna-detail.js .github/workflows/deploy.yml
git commit -m "perf: split data into summary.json and per-CNA detail files"
```

---

### Task 9: Webhook notification for status changes

**Files:**

- Modify: `Code/analyze_cna_anomalies.py`
- Modify: `.github/workflows/deploy.yml`

- [ ] **Step 1: Add status change detection**

Add method to `CVEMonitor`:

```python
def detect_status_changes(self, results: dict[str, Any]) -> list[dict[str, str]]:
    """Compare current results to previous run and detect status changes."""
    changes = []
    previous_file = Path("Web/anomaly_data.json")

    if not previous_file.exists():
        return changes

    try:
        with open(previous_file, "r", encoding="utf-8") as f:
            previous = json.load(f)

        prev_statuses = {c["cna_name"]: c["status"] for c in previous.get("cnas", [])}

        for cna in results["cnas"]:
            prev_status = prev_statuses.get(cna["cna_name"])
            if prev_status and prev_status != cna["status"]:
                changes.append({
                    "cna_name": cna["cna_name"],
                    "cna_org_name": cna.get("cna_org_name", cna["cna_name"]),
                    "previous_status": prev_status,
                    "new_status": cna["status"],
                    "current_count": cna["current_count"],
                    "baseline_avg": cna["baseline_avg"],
                })
    except (json.JSONDecodeError, KeyError):
        pass

    return changes

def send_webhook_notification(self, changes: list[dict[str, str]]) -> None:
    """Send status changes to webhook URL if configured."""
    webhook_url = os.environ.get("CNAPULSE_WEBHOOK_URL")
    if not webhook_url or not changes or not requests:
        return

    payload = {
        "text": f"CNAPulse: {len(changes)} CNA status change(s) detected",
        "changes": changes,
        "generated_at": self.now.isoformat(),
        "dashboard_url": "https://cnapulse.org",
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        if response.ok:
            print(f"Webhook notification sent: {len(changes)} changes")
        else:
            print(f"Webhook notification failed: {response.status_code}")
    except Exception as e:
        print(f"Webhook notification error: {e}")
```

- [ ] **Step 2: Integrate into run()**

Before `self.save_results(results)`:

```python
# Detect and notify on status changes
changes = self.detect_status_changes(results)
if changes:
    print(f"\nDetected {len(changes)} CNA status changes:")
    for change in changes[:10]:
        print(f"  {change['cna_name']}: {change['previous_status']} -> {change['new_status']}")
    self.send_webhook_notification(changes)
```

- [ ] **Step 3: Add optional webhook secret to deploy.yml**

```yaml
- name: Run Anomaly Analysis
  run: |
    python Code/analyze_cna_anomalies.py
  env:
    PYTHONUNBUFFERED: 1
    CNAPULSE_WEBHOOK_URL: ${{ secrets.CNAPULSE_WEBHOOK_URL }}
```

- [ ] **Step 4: Commit**

```bash
git add Code/analyze_cna_anomalies.py .github/workflows/deploy.yml
git commit -m "feat: add webhook notifications for CNA status changes"
```

---

## Phase 3: CI/CD Improvements

### Task 10: Cache cvelistV5 for incremental updates

**Files:**

- Modify: `.github/workflows/deploy.yml`

- [ ] **Step 1: Replace full clone with cached shallow clone + pull**

Replace the "Clone CVE data repository" step:

```yaml
- name: Cache CVE data repository
  id: cache-cve
  uses: actions/cache@v4
  with:
    path: cvelistV5
    key: cvelistv5-${{ github.run_id }}
    restore-keys: |
      cvelistv5-

- name: Clone or update CVE data repository
  run: |
    if [ -d "cvelistV5/.git" ]; then
      echo "Updating cached CVE data..."
      cd cvelistV5
      git pull --depth 1 origin main
      cd ..
    else
      echo "Fresh clone of CVE data..."
      git clone --depth 1 https://github.com/CVEProject/cvelistV5.git cvelistV5
    fi
    echo "CVE data ready"
    ls -la cvelistV5/
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/deploy.yml
git commit -m "perf: cache cvelistV5 repo between CI runs for faster updates"
```

---

### Task 11: Simplify CI error handling

**Files:**

- Modify: `.github/workflows/deploy.yml`

- [ ] **Step 1: Replace retry loop with simple push-or-skip**

Replace the "Commit and push changes" step:

```yaml
- name: Commit and push changes
  if: steps.verify-changed-files.outputs.changed == 'true'
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    git add Web/anomaly_data.json Web/summary.json Web/cna/ Web/history/
    git commit -m "Update CNA anomaly data - $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    git pull --rebase origin main || true
    git push || echo "Push failed - will retry next run in 3 hours"
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/deploy.yml
git commit -m "refactor: simplify CI push logic - skip failures instead of retrying"
```

---

### Task 12: Git history management with squash strategy

**Files:**

- Create: `.github/workflows/squash-history.yml`

- [ ] **Step 1: Create monthly squash workflow**

```yaml
name: Monthly History Squash

on:
  schedule:
    # First day of each month at 02:00 UTC
    - cron: "0 2 1 * *"
  workflow_dispatch:

permissions:
  contents: write

jobs:
  squash-data-commits:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Configure Git
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action"

      - name: Squash old data commits
        run: |
          # Find the commit from 30 days ago
          CUTOFF_DATE=$(date -u -d '30 days ago' '+%Y-%m-%d' 2>/dev/null || date -u -v-30d '+%Y-%m-%d')
          echo "Squashing data-only commits older than $CUTOFF_DATE"

          # Count data commits older than cutoff
          OLD_COMMITS=$(git log --oneline --before="$CUTOFF_DATE" --grep="Update CNA anomaly data" | wc -l)
          echo "Found $OLD_COMMITS old data commits"

          if [ "$OLD_COMMITS" -lt 50 ]; then
            echo "Not enough commits to squash (need 50+). Skipping."
            exit 0
          fi

          # Find the oldest non-data commit or the initial commit
          BASE_COMMIT=$(git log --oneline --before="$CUTOFF_DATE" --invert-grep --grep="Update CNA anomaly data" -1 --format="%H")

          if [ -z "$BASE_COMMIT" ]; then
            echo "No base commit found. Skipping."
            exit 0
          fi

          echo "Base commit: $BASE_COMMIT"
          echo "This workflow is advisory - manual squash recommended for safety"
          echo "Run: git rebase -i $BASE_COMMIT (and squash data commits)"
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/squash-history.yml
git commit -m "ci: add monthly workflow to identify squashable data commits"
```

---

## Phase 4: Frontend Improvements

### Task 13: Favicon for index.html

**Files:**

- Modify: `Web/index.html`

- [ ] **Step 1: Add favicon to index.html head**

Add after the `<meta name="viewport">` line:

```html
<link
  rel="icon"
  href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>📊</text></svg>"
/>
```

- [ ] **Step 2: Commit**

```bash
git add Web/index.html
git commit -m "fix: add missing favicon to index.html"
```

---

### Task 14: Pin CDN dependencies with SRI hashes

**Files:**

- Modify: `Web/index.html`
- Modify: `Web/cna-detail.html`

- [ ] **Step 1: Pin Tailwind CSS CDN with specific version**

Replace in both `index.html` and `cna-detail.html`:

```html
<script src="https://cdn.tailwindcss.com"></script>
```

with:

```html
<script src="https://cdn.tailwindcss.com/3.4.1"></script>
```

- [ ] **Step 2: Pin Chart.js with SRI hash in cna-detail.html**

Replace:

```html
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
```

with:

```html
<script
  src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"
  integrity="sha384-7U0lKag1k5ShcdVuLqBJMsN7MFMFbYqhJGdup6ZwB4MOvhGOjhGcnUV5Q1bFmGF"
  crossorigin="anonymous"
></script>
```

Note: You'll need to verify the actual SRI hash. Generate with:

```bash
curl -s https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js | openssl dgst -sha384 -binary | openssl base64 -A
```

- [ ] **Step 3: Commit**

```bash
git add Web/index.html Web/cna-detail.html
git commit -m "security: pin CDN dependencies to specific versions with SRI"
```

---

### Task 15: Status filter buttons

**Files:**

- Modify: `Web/script.js`
- Modify: `Web/index.html`

- [ ] **Step 1: Make stat cards clickable in index.html**

Replace the stats row cards with clickable versions. Add `cursor-pointer` and `onclick` to each card:

```html
<!-- Stats Row -->
<div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8 fade-in">
  <div
    class="bg-white rounded-lg shadow p-6 border-l-4 border-blue-500 cursor-pointer hover:shadow-lg transition-shadow"
    onclick="filterByStatus('Growth')"
    id="card-growth"
  >
    <!-- ... existing content ... -->
  </div>
  <div
    class="bg-white rounded-lg shadow p-6 border-l-4 border-cyan-500 cursor-pointer hover:shadow-lg transition-shadow"
    onclick="filterByStatus('Normal')"
    id="card-normal"
  >
    <!-- ... existing content ... -->
  </div>
  <div
    class="bg-white rounded-lg shadow p-6 border-l-4 border-indigo-500 cursor-pointer hover:shadow-lg transition-shadow"
    onclick="filterByStatus('Declining')"
    id="card-declining"
  >
    <!-- ... existing content ... -->
  </div>
  <div
    class="bg-white rounded-lg shadow p-6 border-l-4 border-slate-400 cursor-pointer hover:shadow-lg transition-shadow"
    onclick="filterByStatus('Inactive')"
    id="card-inactive"
  >
    <!-- ... existing content ... -->
  </div>
</div>
```

- [ ] **Step 2: Add filterByStatus function to script.js**

```javascript
// Global state
let activeStatusFilter = null;

/**
 * Filter table by clicking status cards
 */
function filterByStatus(status) {
  // Toggle: clicking same status clears filter
  if (activeStatusFilter === status) {
    activeStatusFilter = null;
  } else {
    activeStatusFilter = status;
  }

  // Update card styling to show active filter
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
}
```

- [ ] **Step 3: Update filterAndDisplay to include status filter**

```javascript
function filterAndDisplay() {
  const searchTerm = document.getElementById("cna-search").value.toLowerCase();

  // Start with all CNAs
  filteredCNAs = [...allCNAs];

  // Apply status filter
  if (activeStatusFilter) {
    filteredCNAs = filteredCNAs.filter(
      (cna) => cna.status === activeStatusFilter,
    );
  }

  // Apply search filter
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

  // Reapply current sort
  if (currentSort.column) {
    applySorting();
  }

  updateCNATable(filteredCNAs);
}
```

- [ ] **Step 4: Commit**

```bash
git add Web/index.html Web/script.js
git commit -m "feat: add clickable status filter cards"
```

---

### Task 16: URL-based state (search/sort/filter in query params)

**Files:**

- Modify: `Web/script.js`

- [ ] **Step 1: Add URL state management functions**

```javascript
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
```

- [ ] **Step 2: Integrate URL state into existing flow**

In `DOMContentLoaded`:

```javascript
document.addEventListener("DOMContentLoaded", async () => {
  try {
    await loadAnomalyData();
    readStateFromURL();
    filterAndDisplay();

    document.getElementById("cna-search").addEventListener("input", () => {
      filterAndDisplay();
      writeStateToURL();
    });
  } catch (error) {
    console.error("Error loading anomaly data:", error);
    showError("Failed to load anomaly data. Please try again later.");
  }
});
```

Add `writeStateToURL()` call at the end of `filterByStatus()` and `sortTable()`.

- [ ] **Step 3: Commit**

```bash
git add Web/script.js
git commit -m "feat: persist search/filter/sort state in URL for shareable views"
```

---

### Task 17: Pagination for large table

**Files:**

- Modify: `Web/script.js`
- Modify: `Web/index.html`

- [ ] **Step 1: Add pagination state and controls**

Add to global variables in `script.js`:

```javascript
const PAGE_SIZE = 50;
let currentPage = 1;
```

Add pagination controls HTML after the table's closing `</div>` in `index.html`:

```html
<!-- Pagination -->
<div
  id="pagination"
  class="flex items-center justify-between px-6 py-4 border-t border-gray-200"
  style="display: none;"
>
  <div class="text-sm text-gray-600" id="page-info">
    Showing 1-50 of 545 CNAs
  </div>
  <div class="flex gap-2">
    <button
      onclick="prevPage()"
      id="btn-prev"
      class="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
    >
      Previous
    </button>
    <button
      onclick="nextPage()"
      id="btn-next"
      class="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
    >
      Next
    </button>
  </div>
</div>
```

- [ ] **Step 2: Add pagination functions to script.js**

```javascript
function getPagedCNAs() {
  const start = (currentPage - 1) * PAGE_SIZE;
  const end = start + PAGE_SIZE;
  return filteredCNAs.slice(start, end);
}

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

function nextPage() {
  const totalPages = Math.ceil(filteredCNAs.length / PAGE_SIZE);
  if (currentPage < totalPages) {
    currentPage++;
    updateCNATable(getPagedCNAs());
    updatePagination();
  }
}

function prevPage() {
  if (currentPage > 1) {
    currentPage--;
    updateCNATable(getPagedCNAs());
    updatePagination();
  }
}
```

- [ ] **Step 3: Modify filterAndDisplay to use pagination**

```javascript
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

  // Reset to page 1 on filter change
  currentPage = 1;
  updateCNATable(getPagedCNAs());
  updatePagination();
  writeStateToURL();
}
```

- [ ] **Step 4: Commit**

```bash
git add Web/script.js Web/index.html
git commit -m "feat: add pagination (50 CNAs per page) for better performance"
```

---

### Task 18: Dark mode

**Files:**

- Modify: `Web/index.html`
- Modify: `Web/cna-detail.html`
- Modify: `Web/script.js`

- [ ] **Step 1: Add Tailwind dark mode config and toggle button**

Add to both HTML files, after the Tailwind script tag:

```html
<script>
  tailwind.config = {
    darkMode: "class",
  };
</script>
```

Add dark mode toggle button in the header section of `index.html`:

```html
<!-- Add inside the header div, after the metadata div -->
<button
  onclick="toggleDarkMode()"
  class="fixed top-4 right-4 p-2 rounded-lg bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
  title="Toggle dark mode"
>
  <svg
    id="dark-icon"
    class="w-5 h-5 text-gray-800 hidden"
    fill="currentColor"
    viewBox="0 0 20 20"
  >
    <path
      d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z"
    ></path>
  </svg>
  <svg
    id="light-icon"
    class="w-5 h-5 text-yellow-500 hidden"
    fill="currentColor"
    viewBox="0 0 20 20"
  >
    <path
      fill-rule="evenodd"
      d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z"
      clip-rule="evenodd"
    ></path>
  </svg>
</button>
```

- [ ] **Step 2: Add dark mode classes to body and main containers**

Update `<body>` tag:

```html
<body class="bg-gray-50 dark:bg-gray-900 min-h-screen transition-colors"></body>
```

Update key elements with dark variants:

- Cards: add `dark:bg-gray-800`
- Text: add `dark:text-gray-100` or `dark:text-gray-300`
- Borders: add `dark:border-gray-700`
- Table headers: add `dark:bg-gray-800`
- Table rows: add `dark:bg-gray-800 dark:hover:bg-gray-700`
- Search input: add `dark:bg-gray-800 dark:border-gray-600 dark:text-gray-100`

- [ ] **Step 3: Add toggle function to script.js**

```javascript
/**
 * Dark mode toggle with localStorage persistence
 */
function toggleDarkMode() {
  const html = document.documentElement;
  const isDark = html.classList.toggle("dark");
  localStorage.setItem("cnapulse-dark-mode", isDark ? "dark" : "light");
  updateDarkModeIcons();
}

function updateDarkModeIcons() {
  const isDark = document.documentElement.classList.contains("dark");
  document.getElementById("dark-icon").classList.toggle("hidden", isDark);
  document.getElementById("light-icon").classList.toggle("hidden", !isDark);
}

// Initialize dark mode from localStorage or system preference
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

// Call on load (before DOMContentLoaded to prevent flash)
initDarkMode();
```

- [ ] **Step 4: Commit**

```bash
git add Web/index.html Web/cna-detail.html Web/script.js
git commit -m "feat: add dark mode with system preference detection and toggle"
```

---

### Task 19: Sparkline mini-charts in table

**Files:**

- Modify: `Web/script.js`
- Modify: `Web/index.html`

- [ ] **Step 1: Add sparkline column to table header in index.html**

Add between "Last 30 Days" and "Days Since Last CVE" columns:

```html
<th
  scope="col"
  class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider whitespace-nowrap"
>
  Trend
</th>
```

Update the colspan in loading/empty rows from 6 to 7.

- [ ] **Step 2: Add sparkline SVG generator to script.js**

```javascript
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

  const lastColor = timeline[timeline.length - 1].is_current
    ? "#3b82f6"
    : "#9ca3af";

  return `<svg width="${width}" height="${height}" class="inline-block">
        <polyline points="${points}" fill="none" stroke="${lastColor}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
}
```

- [ ] **Step 3: Add sparkline column to table row rendering**

In the `updateCNATable` function, add after the "Last 30 Days" `<td>`:

```javascript
<td class="px-6 py-4">${generateSparkline(cna.timeline_13months)}</td>
```

Note: Sparklines require timeline data. When loading from `summary.json` (which omits timeline), the sparkline cell will be empty. This is acceptable — sparklines will show when the full `anomaly_data.json` is loaded.

- [ ] **Step 4: Update loadAnomalyData to prefer full data for sparklines**

```javascript
async function loadAnomalyData() {
    try {
        // Load full data (includes timeline for sparklines)
        // Fall back to summary if full data unavailable
        let response = await fetch('anomaly_data.json');
        if (!response.ok) {
            response = await fetch('summary.json');
        }
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        // ... rest unchanged
    }
}
```

- [ ] **Step 5: Commit**

```bash
git add Web/script.js Web/index.html
git commit -m "feat: add sparkline trend charts in table rows"
```

---

### Task 20: Export/download functionality

**Files:**

- Modify: `Web/script.js`
- Modify: `Web/index.html`

- [ ] **Step 1: Add export buttons to index.html**

Add after the search bar, inside the same flex container:

```html
<div class="flex gap-2">
  <button
    onclick="exportCSV()"
    class="px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
    title="Export as CSV"
  >
    CSV
  </button>
  <button
    onclick="exportJSON()"
    class="px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
    title="Export as JSON"
  >
    JSON
  </button>
</div>
```

- [ ] **Step 2: Add export functions to script.js**

```javascript
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
```

- [ ] **Step 3: Commit**

```bash
git add Web/script.js Web/index.html
git commit -m "feat: add CSV and JSON export for filtered CNA data"
```

---

### Task 21: Input validation on URL params

**Files:**

- Modify: `Web/cna-detail.js`

- [ ] **Step 1: Add validation to getCNAFromURL**

```javascript
function getCNAFromURL() {
  const params = new URLSearchParams(window.location.search);
  const cna = params.get("cna");

  if (!cna) return null;

  // Validate: CNA names should be alphanumeric with limited special chars
  // Max length 100, allow letters, numbers, hyphens, underscores, dots, spaces
  if (cna.length > 100) return null;
  if (!/^[\w\s.\-]+$/i.test(cna)) return null;

  return cna;
}
```

- [ ] **Step 2: Commit**

```bash
git add Web/cna-detail.js
git commit -m "security: add input validation for CNA URL parameter"
```

---

### Task 22: Dark mode for cna-detail.html

**Files:**

- Modify: `Web/cna-detail.html`
- Modify: `Web/cna-detail.js`

- [ ] **Step 1: Add dark mode support to cna-detail.html**

Update `<body>`:

```html
<body class="bg-gray-50 dark:bg-gray-900 min-h-screen transition-colors"></body>
```

Add the dark mode toggle button and Tailwind dark config (same as index.html).

Add dark classes to cards, text, and chart container.

- [ ] **Step 2: Add dark mode init to cna-detail.js**

```javascript
// Dark mode initialization (same logic as main page)
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

function toggleDarkMode() {
  const html = document.documentElement;
  const isDark = html.classList.toggle("dark");
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

initDarkMode();
```

- [ ] **Step 3: Update Chart.js colors for dark mode**

In `renderTimelineChart`, detect dark mode and adjust colors:

```javascript
const isDark = document.documentElement.classList.contains('dark');
const gridColor = isDark ? 'rgba(75, 85, 99, 0.5)' : 'rgba(0, 0, 0, 0.1)';
const textColor = isDark ? '#d1d5db' : '#374151';

// Add to chart options.scales:
scales: {
    y: {
        beginAtZero: true,
        grid: { color: gridColor },
        ticks: { color: textColor, /* ... */ },
        title: { display: true, text: 'Number of CVEs Published', color: textColor },
    },
    x: {
        grid: { color: gridColor },
        ticks: { color: textColor, maxRotation: 45, minRotation: 45 },
    },
}
```

- [ ] **Step 4: Commit**

```bash
git add Web/cna-detail.html Web/cna-detail.js
git commit -m "feat: add dark mode to CNA detail page"
```

---

## Phase 5: GitHub Pages Config & Polish

### Task 23: Add caching headers via \_headers file

**Files:**

- Create: `Web/_headers`

- [ ] **Step 1: Create \_headers file for GitHub Pages**

Note: GitHub Pages doesn't support custom `_headers` files (that's Netlify/Cloudflare Pages). Instead, we'll add appropriate meta tags and ensure the data URLs are cache-friendly.

Actually, since GitHub Pages doesn't support custom caching headers, we'll skip this task. The 3-hour update cycle with GitHub Pages CDN provides reasonable caching already.

Alternative: Add a service worker for offline caching.

Create `Web/sw.js`:

```javascript
const CACHE_NAME = "cnapulse-v1";
const STATIC_ASSETS = [
  "/",
  "/index.html",
  "/cna-detail.html",
  "/script.js",
  "/cna-detail.js",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS)),
  );
});

self.addEventListener("fetch", (event) => {
  // Network-first for JSON data, cache-first for static assets
  if (event.request.url.endsWith(".json")) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          const clone = response.clone();
          caches
            .open(CACHE_NAME)
            .then((cache) => cache.put(event.request, clone));
          return response;
        })
        .catch(() => caches.match(event.request)),
    );
  } else {
    event.respondWith(
      caches
        .match(event.request)
        .then((response) => response || fetch(event.request)),
    );
  }
});
```

Register in `index.html` before `</body>`:

```html
<script>
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("sw.js").catch(() => {});
  }
</script>
```

- [ ] **Step 2: Commit**

```bash
git add Web/sw.js Web/index.html
git commit -m "perf: add service worker for offline caching"
```

---

### Task 24: Final integration test and cleanup

**Files:**

- Modify: `tests/test_analyze_cna_anomalies.py`

- [ ] **Step 1: Add integration test that runs full pipeline**

```python
class TestFullPipeline:
    def test_full_run_with_mock_data(self, monitor, sample_cve_data, tmp_path, monkeypatch):
        """Test the full analysis pipeline produces valid output."""
        import os
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Web").mkdir()

        # Skip the file parsing (we provide data directly)
        results = monitor.analyze_cna_activity(sample_cve_data)

        # Verify structure
        assert "metadata" in results
        assert "cnas" in results
        assert "anomalies" in results

        # Save and verify output
        monitor.save_results(results, str(tmp_path / "Web" / "anomaly_data.json"))
        assert (tmp_path / "Web" / "anomaly_data.json").exists()

        # Verify JSON is valid
        import json
        with open(tmp_path / "Web" / "anomaly_data.json") as f:
            loaded = json.load(f)
        assert loaded["metadata"]["total_cnas"] == results["metadata"]["total_cnas"]

    def test_save_split_results(self, monitor, sample_cve_data, tmp_path, monkeypatch):
        """Test split file generation."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "Web").mkdir()

        results = monitor.analyze_cna_activity(sample_cve_data)
        monitor.save_split_results(results)

        # Summary should exist and be smaller than full data
        assert (tmp_path / "Web" / "summary.json").exists()

        # Per-CNA files should exist
        assert (tmp_path / "Web" / "cna").exists()
        cna_files = list((tmp_path / "Web" / "cna").glob("*.json"))
        assert len(cna_files) > 0
```

- [ ] **Step 2: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: All tests pass

- [ ] **Step 3: Run ruff check**

Run: `ruff check Code/ tests/`
Expected: No errors

- [ ] **Step 4: Run mypy**

Run: `mypy Code/ --ignore-missing-imports`
Expected: No errors (or only minor ones)

- [ ] **Step 5: Commit**

```bash
git add tests/
git commit -m "test: add full pipeline integration tests"
```

---

## Summary of Changes

| Phase | Tasks | Description                                                                                               |
| ----- | ----- | --------------------------------------------------------------------------------------------------------- |
| 1     | 1-3   | Project tooling: pyproject.toml, linting, tests                                                           |
| 2     | 4-9   | Analysis: rolling windows, seasonal, metadata, history, split files, webhooks                             |
| 3     | 10-12 | CI/CD: caching, simpler push, squash workflow                                                             |
| 4     | 13-22 | Frontend: favicon, CDN pinning, filters, URL state, pagination, dark mode, sparklines, export, validation |
| 5     | 23-24 | Polish: service worker, integration tests                                                                 |

Total: 24 tasks producing ~24 commits on the `may-update` branch.
