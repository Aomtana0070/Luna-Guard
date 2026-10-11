"""Deterministic synthetic smoke benchmark; contains no live malware samples.

Run from the repository root with: python benchmarks/run_benchmark.py
The generated metrics validate selected code paths, not real-world efficacy.
"""
import argparse
import contextlib
import hashlib
import io
import json
import platform
import statistics
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import luna_guard as lg


SYNTHETIC_XWORM = (
    b"MZ" + b"\0" * 64 + b"mscoree.dll BSJB "
    + "<Xwormmm>".encode("utf-16le") + b" Xklog"
)
CASES = [
    ("synthetic_xworm_markers", True, SYNTHETIC_XWORM, ".exe"),
    ("synthetic_powershell_loader", True,
     b"DownloadString FromBase64String -WindowStyle Hidden #" + b" " * 80, ".ps1"),
    ("synthetic_hidden_powershell", True,
     b"-WindowStyle Hidden -ExecutionPolicy Bypass #" + b" " * 80, ".ps1"),
    ("benign_text", False, b"Luna Guard synthetic benign document. " * 8, ".txt"),
    ("benign_pe_header", False, b"MZ" + b"\0" * 256, ".exe"),
    ("benign_script", False, b"Write-Output 'Hello, world'\n" * 8, ".ps1"),
]


def zip_bytes(members):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_STORED) as archive:
        for name, data in members:
            archive.writestr(name, data)
    return stream.getvalue()


def wrap_zip(content, depth):
    for level in range(depth):
        content = zip_bytes([(f"layer-{level}.zip", content)])
    return content


def archive_case(root, con, name, archive_data, expected_detection,
                 expected_complete, patches=()):
    path = root / f"{name}.zip"
    path.write_bytes(archive_data)
    lg.SCAN_AUDIT.clear()
    lg.SCAN_AUDIT.update(
        issues=0, details=[],
        archive={"archives": 0, "members_seen": 0, "expanded_bytes": 0},
    )
    lg.STOP["flag"] = False
    began = time.perf_counter()
    try:
        with contextlib.ExitStack() as stack:
            for target, value in patches:
                stack.enter_context(mock.patch.object(lg, target, value))
            with contextlib.redirect_stdout(io.StringIO()):
                findings = lg.scan_archive(str(path), con)
    finally:
        lg.STOP["flag"] = False
    elapsed_ms = round((time.perf_counter() - began) * 1000, 3)
    audit = lg.SCAN_AUDIT
    detected = any(item.get("kind") == "Archive member" for item in findings)
    complete = audit.get("issues", 0) == 0
    return {
        "case": name,
        "expected_detection": expected_detection,
        "detected": detected,
        "expected_complete": expected_complete,
        "complete": complete,
        "issues": audit.get("issues", 0),
        "members_seen": audit.get("archive", {}).get("members_seen", 0),
        "expanded_bytes": audit.get("archive", {}).get("expanded_bytes", 0),
        "elapsed_ms": elapsed_ms,
        "correct": detected == expected_detection and complete == expected_complete,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="also write the JSON report to this path")
    args = parser.parse_args()
    rows = []
    started = time.perf_counter()
    old_app_dir, old_db_path = lg.APP_DIR, lg.DB_PATH
    with tempfile.TemporaryDirectory(prefix="luna-benchmark-") as temp:
        root = Path(temp)
        lg.APP_DIR, lg.DB_PATH = root / "data", root / "data" / "threats.db"
        try:
            con = lg.db()
            for name, expected, content, suffix in CASES:
                path = root / (name + suffix)
                path.write_bytes(content)
                began = time.perf_counter()
                severity, reasons, digest = lg.analyze(str(path), con)
                rows.append({
                    "case": name, "kind": "file", "expected_detection": expected,
                    "detected": severity is not None, "severity": severity,
                    "expected_complete": True, "complete": True, "issues": 0,
                    "correct": (severity is not None) == expected,
                    "sha256": digest or hashlib.sha256(content).hexdigest(),
                    "elapsed_ms": round((time.perf_counter() - began) * 1000, 3),
                    "reason_count": len(reasons), "bytes": len(content),
                })

            benign = b"ordinary benchmark text " * 8
            rows.append(archive_case(
                root, con, "benign_archive", zip_bytes([("notes.txt", benign)]),
                False, True,
            ))
            nested = wrap_zip(zip_bytes([("payload.exe", SYNTHETIC_XWORM)]), 4)
            rows.append(archive_case(
                root, con, "nested_synthetic_detection", nested, True, True,
            ))
            too_deep = wrap_zip(
                zip_bytes([("payload.exe", SYNTHETIC_XWORM)]),
                lg.MAX_ARCHIVE_NESTING_DEPTH + 1,
            )
            rows.append(archive_case(
                root, con, "depth_limit_reports_incomplete", too_deep, False, False,
            ))
            large_member = bytes(range(256)) * 4
            rows.append(archive_case(
                root, con, "expanded_limit_reports_incomplete",
                zip_bytes([("bulk.bin", large_member)]), False, False,
                patches=(("MAX_ARCHIVE_EXPANDED_BYTES", 256),),
            ))
            rows.append(archive_case(
                root, con, "member_limit_reports_incomplete",
                zip_bytes([("one.txt", benign), ("two.txt", benign)]), False, False,
                patches=(("MAX_ARCHIVE_MEMBERS", 1),),
            ))
            # A negative time budget exercises the stop path without a slow sleep.
            rows.append(archive_case(
                root, con, "time_limit_reports_incomplete",
                zip_bytes([("one.txt", benign)]), False, False,
                patches=(("MAX_ARCHIVE_SCAN_SECONDS", -1),),
            ))
            con.close()
        finally:
            lg.APP_DIR, lg.DB_PATH = old_app_dir, old_db_path

    file_rows = [row for row in rows if row.get("kind") == "file"]
    tp = sum(row["expected_detection"] and row["detected"] for row in file_rows)
    fp = sum(not row["expected_detection"] and row["detected"] for row in file_rows)
    fn = sum(row["expected_detection"] and not row["detected"] for row in file_rows)
    tn = sum(not row["expected_detection"] and not row["detected"] for row in file_rows)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and precision + recall else None)
    durations = [row["elapsed_ms"] for row in rows]
    report = {
        "benchmark": "Luna Guard synthetic smoke benchmark",
        "scope_note": (
            "Synthetic strings and generated ZIPs only; this is not an AV-TEST, "
            "VirusTotal, or real-world detection efficacy claim."
        ),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "yara_available": bool(lg.yara_rules()),
        "dataset_version": "2",
        "count": len(rows),
        "file_detection": {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
                            "precision": precision, "recall": recall, "f1": f1},
        "timing_ms": {
            "median_per_case": round(statistics.median(durations), 3),
            "max_per_case": round(max(durations), 3),
            "total": round((time.perf_counter() - started) * 1000, 3),
        },
        "all_cases_passed": all(row["correct"] for row in rows),
        "cases": rows,
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    print(encoded, end="")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    return 0 if report["all_cases_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
