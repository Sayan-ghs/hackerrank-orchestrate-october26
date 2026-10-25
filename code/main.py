"""Build deletion-audit answers from the supplied Northstar evidence."""

from __future__ import annotations

import csv
import datetime as dt
import json
import re
import sqlite3
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
EVIDENCE = DATASET / "evidence"

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}


def iso(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def read_csv(name: str) -> list[dict[str, str]]:
    with (DATASET / name).open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def state_for(result: str) -> str:
    value = result.upper()
    return {
        "FOUND": "PRESENT",
        "IDENTIFIABLE": "PRESENT",
        "NOT_FOUND": "ABSENT",
        "ABSENT": "ABSENT",
        "ANONYMIZED": "ANONYMIZED",
        "REDACTED": "REDACTED",
        "ACTIVE": "ACTIVE",
        "DISABLED": "DISABLED",
        "BLOCKED": "BLOCKED",
    }.get(value, value)


def category_for(raw: str) -> str:
    value = raw.upper()
    if "SEARCH" in value:
        return "SEARCH_INDEX_ENTRY"
    if "CACHE" in value:
        return "CACHE_ENTRY"
    if "SUPPORT_ATTACHMENT" in value:
        return "SUPPORT_ATTACHMENT"
    if "SUPPORT_MESSAGE" in value:
        return "SUPPORT_MESSAGE"
    if "ANALYTICS" in value:
        return "ANALYTICS_PROFILE"
    if "TELEMETRY" in value:
        return "PRODUCT_TELEMETRY"
    if "EXPORT" in value:
        return "USER_EXPORT"
    if "MARKETING" in value:
        return "MARKETING_PROFILE"
    if "EMAIL" in value:
        return "EMAIL_DELIVERY_LOG"
    if "SECURITY" in value or "AUDIT" in value:
        return "SECURITY_AUDIT_LOG"
    if "LEGAL" in value:
        return "LEGAL_HOLD_RECORD"
    if "BACKUP" in value:
        return "BACKUP_ARCHIVE"
    if "TOMBSTONE" in value:
        return "ACCOUNT_TOMBSTONE"
    if "FLOW" in value or "CONNECTOR" in value:
        return "DATA_FLOW"
    return "USER_PROFILE"


def resource_system(resource: str) -> str:
    prefix = resource.split("_", 1)[0]
    return {
        "account": "account_service",
        "search": "search_service",
        "analytics": "analytics_platform",
        "support": "support_platform",
        "export": "export_service",
        "backup": "backup_service",
        "cache": "cache_service",
        "data": "integration_service",
        "audit": "security_service",
        "tombstone": "identity_service",
        "marketing": "marketing_platform",
        "email": "email_delivery_service",
        "object": "object_storage",
    }.get(prefix, "")


def resource_category(resource: str) -> str:
    prefix = resource.split("_", 1)[0]
    return {
        "account": "USER_PROFILE",
        "search": "SEARCH_INDEX_ENTRY",
        "analytics": "ANALYTICS_PROFILE",
        "support": "SUPPORT_MESSAGE",
        "export": "USER_EXPORT",
        "backup": "BACKUP_ARCHIVE",
        "cache": "CACHE_ENTRY",
        "data": "DATA_FLOW",
        "audit": "SECURITY_AUDIT_LOG",
        "tombstone": "ACCOUNT_TOMBSTONE",
        "marketing": "MARKETING_PROFILE",
        "email": "EMAIL_DELIVERY_LOG",
        "object": "SUPPORT_ATTACHMENT",
    }.get(prefix, "USER_PROFILE")


def extract_text_file(path: Path) -> str:
    if path.suffix.lower() == ".pdf":
        try:
            result = subprocess.run(
                ["pdftotext", "-layout", str(path), "-"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""
    return path.read_text(encoding="utf-8", errors="replace")


def evidence_timestamp(path: Path, manifest: dict[str, dict[str, str]]) -> dt.datetime:
    return iso(manifest[str(path.relative_to(DATASET).as_posix())]["captured_at"])


def load_manifest() -> dict[str, dict[str, str]]:
    return {row["file_path"]: row for row in read_csv("evidence_files.csv")}


def load_identities() -> tuple[dict[str, set[str]], dict[str, str]]:
    identities = read_csv("user_identities.csv")
    aliases: dict[str, set[str]] = defaultdict(set)
    alias_to_user: dict[str, str] = {}
    for row in identities:
        user = row["user_id"]
        for key in ("email", "phone", "email_hash", "name"):
            if row.get(key):
                aliases[user].add(row[key].strip().lower())
                alias_to_user[row[key].strip().lower()] = user
    for row in read_csv("user_audit_log.csv"):
        user = row["user_id"]
        for key in ("old_value", "new_value"):
            if row.get(key):
                aliases[user].add(row[key].strip().lower())
                alias_to_user[row[key].strip().lower()] = user
    return aliases, alias_to_user


def collect_observations(
    manifest: dict[str, dict[str, str]], aliases: dict[str, set[str]], activity: list[dict[str, str]]
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []

    def add(
        captured: dt.datetime,
        evidence_id: str,
        system: str,
        resource: str,
        category: str,
        result: str,
        subjects: set[str],
    ) -> None:
        if resource and subjects:
            known_systems = {
                "account_service", "search_service", "analytics_platform",
                "support_platform", "export_service", "backup_service",
                "cache_service", "integration_service", "security_service",
                "identity_service", "marketing_platform", "email_delivery_service",
                "object_storage",
            }
            if not system or system not in known_systems:
                system = resource_system(resource) or system
            category = category_for(category or resource_category(resource))
            observations.append(
                {
                    "captured": captured,
                    "evidence_id": evidence_id,
                    "system": system,
                    "resource": resource,
                    "category": category_for(category),
                    "state": state_for(result),
                    "subjects": subjects,
                }
            )

    def walk(value: Any, captured: dt.datetime, evidence_id: str, inherited: str = "") -> None:
        if isinstance(value, dict):
            resource = str(value.get("resource_id", ""))
            system = str(value.get("system") or value.get("data_store") or inherited)
            category = str(
                value.get("record_type")
                or value.get("data_category")
                or value.get("collection")
                or value.get("type")
                or inherited
            )
            result = str(value.get("result") or value.get("state") or value.get("status") or "")
            if resource:
                values = {text(v).strip().lower() for v in value.values() if text(v).strip()}
                add(captured, evidence_id, system, resource, category, result, values)
            for child in value.values():
                walk(child, captured, evidence_id, system)
        elif isinstance(value, list):
            for child in value:
                walk(child, captured, evidence_id, inherited)

    for path in sorted(EVIDENCE.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(DATASET).as_posix()
        if relative not in manifest:
            continue
        evidence_id = manifest[relative]["file_id"]
        captured = evidence_timestamp(path, manifest)
        if path.suffix.lower() == ".json":
            try:
                walk(json.loads(path.read_text(encoding="utf-8")), captured, evidence_id)
            except json.JSONDecodeError:
                pass
        elif path.suffix.lower() == ".sql":
            connection = sqlite3.connect(":memory:")
            try:
                connection.executescript(path.read_text(encoding="utf-8", errors="replace"))
                for table, in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ):
                    cursor = connection.execute(f'SELECT * FROM "{table}"')
                    columns = [item[0] for item in cursor.description]
                    for row in cursor:
                        record = dict(zip(columns, row))
                        resource = str(
                            record.get("resource_id")
                            or record.get("account_id")
                            or record.get("id")
                            or ""
                        )
                        values = {text(v).strip().lower() for v in record.values() if text(v).strip()}
                        add(
                            captured,
                            evidence_id,
                            table,
                            resource,
                            table,
                            str(record.get("state") or record.get("status") or record.get("result") or ""),
                            values,
                        )
            except sqlite3.Error:
                pass
            finally:
                connection.close()
        else:
            content = extract_text_file(path)
            for line in content.splitlines():
                resources = re.findall(
                    r"\b(?:account|search|analytics|support|export|backup|cache|"
                    r"data_flow|audit_record|tombstone|marketing|email_delivery|object)_\d+\b",
                    line,
                    flags=re.IGNORECASE,
                )
                if not resources:
                    continue
                lowered = line.lower()
                system = next(
                    (
                        candidate
                        for candidate in (
                            "account_service",
                            "search_service",
                            "analytics_platform",
                            "support_platform",
                            "export_service",
                            "backup_service",
                            "integration_service",
                            "security_service",
                            "marketing_platform",
                            "email_delivery_service",
                        )
                        if candidate in lowered
                    ),
                    "",
                )
                category = next(
                    (part for part in ("USER_PROFILE", "SEARCH_INDEX_ENTRY", "ANALYTICS_PROFILE",
                                     "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "BACKUP_ARCHIVE",
                                     "DATA_FLOW", "SECURITY_AUDIT_LOG", "USER_EXPORT")
                     if part.lower() in lowered),
                    "",
                )
                result = next(
                    (part for part in ("NOT_FOUND", "FOUND", "IDENTIFIABLE", "ANONYMIZED",
                                       "REDACTED", "ACTIVE", "DISABLED", "BLOCKED")
                     if part.lower() in lowered),
                    "",
                )
                if not result:
                     if re.search(r"\b(?:rows|row_count)\s*=\s*[\"']?0\b", lowered) or "http_status=404" in lowered:
                         result = "NOT_FOUND"
                     elif re.search(r"\bhttp_status=200\b", lowered):
                         result = "FOUND"
                subjects = {part.strip(" ,;:()[]").lower() for part in re.split(r"\s+", line)}
                for resource in resources:
                    add(captured, evidence_id, system, resource, category, result, subjects)

    for row in activity:
        details = row["details"].lower()
        subjects = set(re.findall(r"[\w.+-]+@[\w.-]+\.\w+|user_\d+", details))
        if not subjects:
            continue
        kind = row["event_type"]
        result = {
            "DELETE_RECORD": "ABSENT",
            "ANONYMIZE_RECORD": "ANONYMIZED",
            "REDACT_RECORD": "REDACTED",
            "DISABLE_DATA_FLOW": "DISABLED",
            "BLOCK_RESTORE": "BLOCKED",
            "CHECK_DATA_FLOW": "ACTIVE" if "active" in details else "DISABLED",
            "CHECK_RESTORE_ACCESS": "ACTIVE" if "can still" in details else "BLOCKED",
            "RESTORE_BACKUP": "ACTIVE",
        }.get(kind, "")
        category = "DATA_FLOW" if "FLOW" in kind else "BACKUP_ARCHIVE" if "RESTORE" in kind else kind
        add(
            iso(row["event_time"]),
            row["activity_id"],
            row["target_system"],
            row["resource_id"],
            category,
            result,
            subjects,
        )
    return observations


def deletion_requested(request: dict[str, str]) -> bool:
    lowered = request["request_text"].lower()
    if any(phrase in lowered for phrase in ("not asking for deletion", "do not close", "still need the account")):
        return False
    # The input is a deletion-request queue; multilingual templates may not
    # contain an English deletion token.
    return True


def operation_for(category: str, state: str) -> tuple[str, str, str] | None:
    if category in {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
                    "SUPPORT_ATTACHMENT", "USER_EXPORT", "MARKETING_PROFILE", "EMAIL_DELIVERY_LOG"}:
        if state not in {"ABSENT"}:
            return "DELETE_RECORD", "ABSENT", "REPORT_REMAINING_RECORD"
        return None
    if category == "SUPPORT_MESSAGE":
        if state == "PRESENT":
            return "REDACT_RECORD", "REDACTED", "REPORT_EXPOSED_PII"
        return None
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        if state not in {"ANONYMIZED", "ABSENT"}:
            return "ANONYMIZE_RECORD", "ANONYMIZED", "REPORT_EXPOSED_PII"
        return None
    if category == "ACCOUNT_TOMBSTONE":
        if state not in {"REDACTED", "ABSENT"}:
            return "REDACT_RECORD", "REDACTED", "REPORT_EXPOSED_PII"
        return None
    return None


def build_steps(
    request: dict[str, str], observations: list[dict[str, Any]], aliases: dict[str, set[str]], alias_to_user: dict[str, str]
) -> tuple[str, list[dict[str, Any]]]:
    if not deletion_requested(request):
        return "NOT_APPLICABLE", []
    user = alias_to_user.get(request["email"].strip().lower())
    subjects = aliases.get(user, {request["email"].strip().lower()})
    cutoff = iso(request["audit_at"])
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for item in observations:
        if item["captured"] > cutoff:
            continue
        if not any(subject in item["subjects"] for subject in subjects):
            continue
        key = (item["system"], item["resource"])
        if key not in latest or item["captured"] >= latest[key]["captured"]:
            latest[key] = item

    findings: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []
    verifications: list[dict[str, Any]] = []
    for item in latest.values():
        operation = operation_for(item["category"], item["state"])
        if item["category"] == "DATA_FLOW" and item["state"] == "ACTIVE":
            findings.append({**item, "operation": "REPORT_ACTIVE_DATA_FLOW", "state": "ACTIVE"})
            remediations.append({**item, "operation": "DISABLE_DATA_FLOW", "state": "DISABLED"})
        elif item["category"] == "BACKUP_ARCHIVE" and item["state"] == "ACTIVE":
            findings.append({**item, "operation": "REPORT_RESTORE_RISK", "state": "ACTIVE"})
            remediations.append({**item, "operation": "BLOCK_RESTORE", "state": "BLOCKED"})
        elif operation:
            remediation, desired, finding = operation
            findings.append({**item, "operation": finding, "state": "PRESENT"})
            remediations.append({**item, "operation": remediation, "state": desired})

        if item["category"] == "SECURITY_AUDIT_LOG" or item["category"] == "LEGAL_HOLD_RECORD":
            verifications.append({**item, "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT"})
        elif item["category"] == "DATA_FLOW":
            verifications.append({**item, "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED"})
        elif item["category"] == "BACKUP_ARCHIVE":
            verifications.append({**item, "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED"})
        elif item["category"] == "SUPPORT_MESSAGE" and item["state"] in {"PRESENT", "REDACTED"}:
            verifications.append({**item, "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED"})
        elif item["category"] in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
            verifications.append({**item, "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED"})
        elif item["category"] == "ACCOUNT_TOMBSTONE":
            verifications.append({**item, "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED"})
        else:
            verifications.append({**item, "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT"})

    def sort_key(item: dict[str, Any]) -> tuple[int, str, str]:
        return (OPERATION_ORDER[item["operation"]], item["system"], item["resource"])

    findings.sort(key=sort_key)
    remediations.sort(key=sort_key)
    verifications.sort(key=sort_key)
    incomplete = bool(findings or remediations)
    selected = findings + remediations + verifications
    steps = []
    for number, item in enumerate(selected, 1):
        phase = "FINDING" if item in findings else "REMEDIATION" if item in remediations else "VERIFICATION"
        steps.append(
            {
                "step_no": number,
                "phase": phase,
                "system_id": item["system"],
                "resource_id": item["resource"],
                "operation": item["operation"],
                "state": item["state"],
                "evidence_id": item["evidence_id"] if not incomplete or phase == "FINDING" else "",
            }
        )
    return ("INCOMPLETE" if incomplete else "COMPLETE"), steps


def main() -> None:
    request_file = sys.argv[1] if len(sys.argv) > 1 else "deletion_requests.csv"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "output.csv"
    manifest = load_manifest()
    identities, alias_to_user = load_identities()
    activity = read_csv("system_activity.csv")
    observations = collect_observations(manifest, identities, activity)
    output = []
    for request in read_csv(request_file):
        status, steps = build_steps(request, observations, identities, alias_to_user)
        output.append({"case_id": request["case_id"], "deletion_status": status, "steps_json": json.dumps(steps, separators=(",", ":"))})
    output.sort(key=lambda row: int(row["case_id"].rsplit("_", 1)[1]))
    with (DATASET / output_file).open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(output)


if __name__ == "__main__":
    main()