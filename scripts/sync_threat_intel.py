#!/usr/bin/env python3
"""Build an Enumscan threat-intelligence delta from authoritative public feeds."""

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import ssl
import time
import urllib.parse
import urllib.request

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
MAX_SOURCE_BYTES = 256 << 20


def fetch(url, headers=None, limit=MAX_SOURCE_BYTES):
    if urllib.parse.urlparse(url).scheme != "https":
        raise ValueError("threat-intelligence sources must use HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "enumscan-threat-intel/1", **(headers or {})})
    last_error = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=60, context=ssl.create_default_context()) as response:
                data = response.read(limit + 1)
                if len(data) > limit:
                    raise ValueError("source exceeds size limit")
                return data
        except Exception as error:  # bounded retry is intentional for scheduled operations
            last_error = error
            if attempt < 2:
                time.sleep(attempt + 1)
    raise RuntimeError(f"fetch {url}: {last_error}")


def nvd_pages(base_url, start, end, api_key=""):
    start_index, total = 0, None
    headers = {"apiKey": api_key} if api_key else {}
    while total is None or start_index < total:
        query = urllib.parse.urlencode({
            "lastModStartDate": start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "lastModEndDate": end.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "startIndex": start_index,
            "resultsPerPage": 2000,
        })
        raw = fetch(base_url + "?" + query, headers)
        payload = json.loads(raw)
        total = int(payload.get("totalResults", 0))
        vulnerabilities = payload.get("vulnerabilities", [])
        yield raw, vulnerabilities
        if not vulnerabilities:
            break
        start_index += len(vulnerabilities)
        if start_index < total:
            time.sleep(0.6 if api_key else 6.0)


def parse_kev(raw):
    payload = json.loads(raw)
    return {item.get("cveID") for item in payload.get("vulnerabilities", []) if item.get("cveID")}


def parse_epss(raw):
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        text = io.TextIOWrapper(stream, encoding="utf-8")
        first = text.readline()
        if not first.startswith("#"):
            text.seek(0)
        scores = {}
        for row in csv.DictReader(text):
            try:
                scores[row["cve"]] = float(row["epss"])
            except (KeyError, TypeError, ValueError):
                continue
        return scores


def english_description(cve):
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return description.get("value", "")[:8000]
    return ""


def first_cwe(cve):
    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if value.startswith("CWE-"):
                return value
    return ""


def cvss_score(cve):
    metrics = cve.get("metrics", {})
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(name, [])
        if values:
            try:
                return float(values[0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                pass
    return 0.0


def cpe_matches(cve):
    result = []
    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and match.get("criteria"):
                    result.append(match)
    return result


def transform(vulnerabilities, kev, epss):
    entries = []
    for wrapper in vulnerabilities:
        cve = wrapper.get("cve", {})
        cve_id = cve.get("id", "")
        matches = cpe_matches(cve) or [{}]
        references = [item.get("url") for item in cve.get("references", []) if item.get("url")][:50]
        for match in matches:
            entries.append({
                "cve_id": cve_id,
                "cwe_id": first_cwe(cve),
                "cvss": cvss_score(cve),
                "epss": epss.get(cve_id, 0.0),
                "kev": cve_id in kev,
                "description": english_description(cve),
                "target_cpe": match.get("criteria", ""),
                "min_version": match.get("versionStartIncluding", match.get("versionStartExcluding", "")),
                "max_version": match.get("versionEndIncluding", match.get("versionEndExcluding", "")),
                "min_exclusive": "versionStartExcluding" in match,
                "max_exclusive": "versionEndExcluding" in match,
                "references": references,
            })
    return entries


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--days", type=int, default=2)
    parser.add_argument("--nvd-url", default=NVD_URL)
    parser.add_argument("--kev-url", default=KEV_URL)
    parser.add_argument("--epss-url", default=EPSS_URL)
    parser.add_argument("--nvd-api-key-env", default="NVD_API_KEY")
    args = parser.parse_args()
    if args.days < 1 or args.days > 120:
        raise SystemExit("--days must be between 1 and 120")

    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(days=args.days)
    kev_raw, epss_raw = fetch(args.kev_url), fetch(args.epss_url)
    kev, epss = parse_kev(kev_raw), parse_epss(epss_raw)
    nvd_hashes, vulnerabilities = [], []
    for raw, page in nvd_pages(args.nvd_url, start, end, os.getenv(args.nvd_api_key_env, "")):
        nvd_hashes.append(sha256(raw))
        vulnerabilities.extend(page)
    entries = transform(vulnerabilities, kev, epss)
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with open(args.output, "wb") as output:
        output.write(encoded)
    metadata = {
        "schema": "enumscan-threat-intelligence-v1",
        "generated_at": end.isoformat(),
        "window_start": start.isoformat(),
        "entry_count": len(entries),
        "output_sha256": sha256(encoded),
        "sources": {
            "nvd": {"url": args.nvd_url, "page_sha256": nvd_hashes},
            "cisa_kev": {"url": args.kev_url, "sha256": sha256(kev_raw)},
            "first_epss": {"url": args.epss_url, "sha256": sha256(epss_raw)},
        },
    }
    with open(args.metadata, "w", encoding="utf-8") as output:
        json.dump(metadata, output, indent=2, sort_keys=True)
        output.write("\n")


if __name__ == "__main__":
    main()
