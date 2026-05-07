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
        {
            "cveId": "CVE-2026-9001",
            "datePublished": "2026-04-28T10:00:00",
            "assignerOrgId": "uuid-new-cna",
            "assignerShortName": "NewCNA",
        },
    ]
