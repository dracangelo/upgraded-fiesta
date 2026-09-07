import gzip
import importlib.util
import io
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("sync_threat_intel.py")
SPEC = importlib.util.spec_from_file_location("sync_threat_intel", MODULE_PATH)
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)


class ThreatIntelTransformTests(unittest.TestCase):
    def test_merges_nvd_kev_and_epss(self):
        vulnerability = {"cve": {"id": "CVE-2026-0001", "descriptions": [{"lang": "en", "value": "Example"}], "weaknesses": [{"description": [{"value": "CWE-79"}]}], "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}]}, "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "versionEndIncluding": "2.0"}]}]}], "references": [{"url": "https://example.test/advisory"}]}}
        result = SYNC.transform([vulnerability], {"CVE-2026-0001"}, {"CVE-2026-0001": 0.91})
        self.assertEqual(result[0]["cwe_id"], "CWE-79")
        self.assertEqual(result[0]["max_version"], "2.0")
        self.assertTrue(result[0]["kev"])
        self.assertEqual(result[0]["epss"], 0.91)

    def test_parses_compressed_epss(self):
        raw = io.BytesIO()
        with gzip.GzipFile(fileobj=raw, mode="wb") as stream:
            stream.write(b"#model_version:v1\ncve,epss,percentile\nCVE-2026-0001,0.42,0.8\n")
        self.assertEqual(SYNC.parse_epss(raw.getvalue())["CVE-2026-0001"], 0.42)


if __name__ == "__main__":
    unittest.main()
