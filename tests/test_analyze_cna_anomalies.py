from datetime import datetime


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


class TestRollingWindowBaseline:
    def test_baseline_uses_rolling_windows(self, monitor):
        """Baseline should use 12 rolling 30-day windows, not calendar months."""
        from datetime import timedelta

        cve_data = []
        # 2 CVEs per 30-day window for 6 windows in baseline
        for i in range(6):
            days_ago = 60 + (i * 30)
            for j in range(2):
                cve_data.append(
                    {
                        "cveId": f"CVE-2025-{i}{j}",
                        "datePublished": (monitor.now - timedelta(days=days_ago + j)).isoformat(),
                        "assignerOrgId": "uuid-test",
                        "assignerShortName": "TestCNA",
                    }
                )
        # 5 CVEs in the current monitoring window
        for i in range(5):
            cve_data.append(
                {
                    "cveId": f"CVE-2026-{i}",
                    "datePublished": (monitor.now - timedelta(days=i + 1)).isoformat(),
                    "assignerOrgId": "uuid-test",
                    "assignerShortName": "TestCNA",
                }
            )

        results = monitor.analyze_cna_activity(cve_data)
        cna = next(c for c in results["cnas"] if c["cna_name"] == "TestCNA")
        # Baseline avg should be 2.0 (2 CVEs per 30-day window, averaged over 6 active windows)
        assert 1.5 <= cna["baseline_avg"] <= 2.5


class TestSeasonalNormalization:
    def test_seasonal_factor_low_season(self, monitor):
        """Low season should produce factor < 1."""
        # Window 0 = 1 month ago (April), window 11 = 12 months ago (May last year)
        # If current is May, same-season windows would be around index 0 (April) and 11 (May)
        # Make those low, everything else high
        monthly_counts = [1, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 1]
        factor = monitor.calculate_seasonal_factor(monthly_counts)
        assert factor < 1.0

    def test_seasonal_factor_high_season(self, monitor):
        """High season should produce factor > 1."""
        monthly_counts = [10, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 10]
        factor = monitor.calculate_seasonal_factor(monthly_counts)
        assert factor > 1.0

    def test_seasonal_factor_uniform(self, monitor):
        """Uniform data should produce factor ~1.0."""
        monthly_counts = [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5]
        factor = monitor.calculate_seasonal_factor(monthly_counts)
        assert 0.9 <= factor <= 1.1

    def test_seasonal_factor_insufficient_data(self, monitor):
        """Fewer than 6 data points should return 1.0."""
        factor = monitor.calculate_seasonal_factor([1, 2, 3])
        assert factor == 1.0

    def test_seasonal_factor_empty(self, monitor):
        """Empty data should return 1.0."""
        factor = monitor.calculate_seasonal_factor([])
        assert factor == 1.0
