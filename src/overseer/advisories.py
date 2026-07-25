"""CVE and security advisory feed cache for O'Brien."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable
from urllib.parse import urlencode

DEFAULT_ADVISORY_PACKAGES = ("openssl", "openssh", "sudo", "curl", "apt", "dpkg", "systemd", "python3")
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEBIAN_TRACKER_JSON = "https://security-tracker.debian.org/tracker/data/json"
FeedFetcher = Callable[[str, dict[str, str], float], dict[str, object]]


def advisory_cache_dir(store_path: str | Path) -> Path:
    path = Path(store_path).resolve()
    root = path.parent
    if root.name != "state":
        root = path.parent / "state"
    return root / "advisory-cache"


def advisory_status(store_path: str | Path, package_names: list[str] | tuple[str, ...] | None = None) -> dict[str, object]:
    packages = _normal_package_names(package_names)
    cache_dir = advisory_cache_dir(store_path)
    cache_dir.mkdir(parents=True, exist_ok=True)
    records = [_read_cache_file(path) for path in sorted(cache_dir.glob("*.json"))]
    records = [record for record in records if record]
    findings = []
    for record in records:
        if packages and record.get("package") not in packages:
            continue
        findings.extend(record.get("findings") or [])

    package_summary = _package_summary(packages, findings, records)
    return {
        "status": "configured",
        "sources": _feed_sources(),
        "cache_dir": str(cache_dir),
        "requested_packages": packages,
        "cached_packages": sorted({str(record.get("package")) for record in records if record.get("package")}),
        "cached_records": len(records),
        "findings": sorted(findings, key=_finding_sort_key),
        "finding_count": len(findings),
        "by_severity": _severity_counts(findings),
        "package_summary": package_summary,
        "oldest_cache_age_seconds": _oldest_cache_age_seconds(records),
        "next_step": "refresh advisories" if not records else "review advisory findings before package execution",
        "mutation_performed": False,
        "host_mutation_performed": False,
        "external_request_performed": False,
    }


def refresh_advisories_status(
    store_path: str | Path,
    package_names: list[str] | tuple[str, ...] | None = None,
    source: str = "nvd",
    max_results_per_package: int = 5,
    requested_by: str = "obrien",
    dry_run: bool = False,
    fetcher: FeedFetcher | None = None,
) -> dict[str, object]:
    packages = _normal_package_names(package_names)
    source = _normal_source(source)
    max_results = max(1, min(int(max_results_per_package), 20))
    cache_dir = advisory_cache_dir(store_path)
    cache_dir.mkdir(parents=True, exist_ok=True)
    fetched_at = _now_iso()
    if dry_run:
        return {
            "status": "dry_run",
            "source": source,
            "packages": packages,
            "max_results_per_package": max_results,
            "requested_by": requested_by,
            "endpoints": _source_endpoints(source),
            "next_step": "run without dry_run to refresh the local advisory cache",
            "mutation_performed": False,
            "host_mutation_performed": False,
            "external_request_performed": False,
        }

    fetched_records = []
    active_fetcher = fetcher or _fetch_json
    if source in {"nvd", "both"}:
        for package in packages:
            findings = _fetch_nvd_package(package, max_results, active_fetcher)
            record = _cache_record("nvd", package, fetched_at, findings, NVD_CVE_API)
            _write_cache_file(cache_dir / f"nvd-{_safe_name(package)}.json", record)
            fetched_records.append(record)
    if source in {"debian", "both"}:
        debian_payload = active_fetcher(DEBIAN_TRACKER_JSON, {}, 20.0)
        for package in packages:
            findings = _parse_debian_package(package, debian_payload, max_results)
            record = _cache_record("debian", package, fetched_at, findings, DEBIAN_TRACKER_JSON)
            _write_cache_file(cache_dir / f"debian-{_safe_name(package)}.json", record)
            fetched_records.append(record)

    return {
        "status": "refreshed",
        "source": source,
        "packages": packages,
        "records": len(fetched_records),
        "finding_count": sum(len(record["findings"]) for record in fetched_records),
        "findings": [finding for record in fetched_records for finding in record["findings"]],
        "cache_dir": str(cache_dir),
        "requested_by": requested_by,
        "mutation_performed": True,
        "host_mutation_performed": False,
        "external_request_performed": True,
    }


def _fetch_nvd_package(package: str, max_results: int, fetcher: FeedFetcher) -> list[dict[str, object]]:
    query = urlencode({"keywordSearch": package, "resultsPerPage": max_results, "startIndex": 0})
    payload = fetcher(f"{NVD_CVE_API}?{query}", {}, 15.0)
    findings = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            continue
        findings.append(_nvd_finding(package, cve))
    return findings[:max_results]


def _nvd_finding(package: str, cve: dict[str, object]) -> dict[str, object]:
    metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
    severity, score = _nvd_metric(metrics)
    references = cve.get("references") if isinstance(cve.get("references"), list) else []
    url = ""
    if references and isinstance(references[0], dict):
        url = str(references[0].get("url") or "")
    cve_id = str(cve.get("id") or "")
    return {
        "package": package,
        "source": "nvd",
        "cve_id": cve_id,
        "severity": severity,
        "score": score,
        "published": str(cve.get("published") or ""),
        "last_modified": str(cve.get("lastModified") or ""),
        "status": str(cve.get("vulnStatus") or ""),
        "summary": _english_description(cve.get("descriptions")),
        "url": url or f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
    }


def _parse_debian_package(package: str, payload: dict[str, object], max_results: int) -> list[dict[str, object]]:
    package_payload = payload.get(package)
    if not isinstance(package_payload, dict):
        return []
    findings = []
    for cve_id, details in sorted(package_payload.items()):
        if not isinstance(details, dict):
            continue
        releases = details.get("releases") if isinstance(details.get("releases"), dict) else {}
        urgency = str(details.get("urgency") or _release_urgency(releases) or "unknown")
        findings.append(
            {
                "package": package,
                "source": "debian",
                "cve_id": str(cve_id),
                "severity": _debian_severity(urgency),
                "score": None,
                "published": "",
                "last_modified": "",
                "status": str(details.get("scope") or ""),
                "summary": str(details.get("description") or details.get("notes") or ""),
                "url": f"https://security-tracker.debian.org/tracker/{cve_id}",
                "debian_urgency": urgency,
            }
        )
    return findings[:max_results]


def _fetch_json(url: str, headers: dict[str, str], timeout: float) -> dict[str, object]:
    request = urllib.request.Request(url, headers={"Accept": "application/json", **headers})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"advisory feed request failed for {url}: {exc}") from exc


def _cache_record(source: str, package: str, fetched_at: str, findings: list[dict[str, object]], endpoint: str) -> dict[str, object]:
    return {
        "source": source,
        "package": package,
        "fetched_at": fetched_at,
        "endpoint": endpoint,
        "findings": findings,
    }


def _write_cache_file(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_cache_file(path: Path) -> dict[str, object] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _normal_package_names(package_names: list[str] | tuple[str, ...] | None) -> list[str]:
    names = list(package_names or DEFAULT_ADVISORY_PACKAGES)
    normalized = []
    for raw in names:
        name = str(raw).strip().lower()
        if name and re.fullmatch(r"[a-z0-9][a-z0-9+_.-]{0,79}", name):
            normalized.append(name)
    return sorted(dict.fromkeys(normalized))


def _normal_source(source: str) -> str:
    source = str(source or "nvd").strip().lower()
    if source not in {"nvd", "debian", "both"}:
        raise ValueError("source must be nvd, debian, or both")
    return source


def _nvd_metric(metrics: dict[str, object]) -> tuple[str, float | None]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if not isinstance(values, list) or not values:
            continue
        first = values[0]
        if not isinstance(first, dict):
            continue
        data = first.get("cvssData") if isinstance(first.get("cvssData"), dict) else {}
        severity = str(first.get("baseSeverity") or data.get("baseSeverity") or "unknown").lower()
        score = data.get("baseScore")
        return severity, score if isinstance(score, int | float) else None
    return "unknown", None


def _english_description(descriptions: object) -> str:
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en":
            return str(item.get("value") or "")
    return ""


def _debian_severity(urgency: str) -> str:
    normalized = urgency.lower()
    if "high" in normalized:
        return "high"
    if "medium" in normalized:
        return "medium"
    if "low" in normalized:
        return "low"
    if "unimportant" in normalized:
        return "low"
    return "unknown"


def _release_urgency(releases: dict[str, object]) -> str:
    for details in releases.values():
        if isinstance(details, dict) and details.get("urgency"):
            return str(details["urgency"])
    return ""


def _package_summary(packages: list[str], findings: list[dict[str, object]], records: list[dict[str, object]]) -> list[dict[str, object]]:
    names = sorted(set(packages) | {str(record.get("package")) for record in records if record.get("package")})
    rows = []
    for package in names:
        package_findings = [finding for finding in findings if finding.get("package") == package]
        counts = _severity_counts(package_findings)
        rows.append(
            {
                "package": package,
                "findings": len(package_findings),
                "critical": counts.get("critical", 0),
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
                "next_step": "review before update" if package_findings else "refresh or no cached findings",
            }
        )
    return rows


def _severity_counts(findings: list[dict[str, object]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown").lower()
        if severity not in counts:
            severity = "unknown"
        counts[severity] += 1
    return counts


def _oldest_cache_age_seconds(records: list[dict[str, object]]) -> int | None:
    ages = []
    now = datetime.now(UTC)
    for record in records:
        fetched_at = str(record.get("fetched_at") or "")
        try:
            captured = datetime.fromisoformat(fetched_at.replace("Z", "+00:00"))
        except ValueError:
            continue
        ages.append(int((now - captured).total_seconds()))
    return max(ages) if ages else None


def _finding_sort_key(finding: dict[str, object]) -> tuple[int, str, str]:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    return (
        severity_order.get(str(finding.get("severity") or "unknown").lower(), 4),
        str(finding.get("package") or ""),
        str(finding.get("cve_id") or ""),
    )


def _source_endpoints(source: str) -> list[str]:
    endpoints = []
    if source in {"nvd", "both"}:
        endpoints.append(NVD_CVE_API)
    if source in {"debian", "both"}:
        endpoints.append(DEBIAN_TRACKER_JSON)
    return endpoints


def _feed_sources() -> list[dict[str, object]]:
    return [
        {
            "source": "nvd",
            "name": "NVD CVE API 2.0",
            "url": NVD_CVE_API,
            "status": "available_on_refresh",
        },
        {
            "source": "debian",
            "name": "Debian Security Tracker JSON",
            "url": DEBIAN_TRACKER_JSON,
            "status": "available_on_refresh",
        },
    ]


def _safe_name(value: str) -> str:
    return re.sub(r"[^a-z0-9+_.-]+", "-", value.lower()).strip("-") or "package"


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
