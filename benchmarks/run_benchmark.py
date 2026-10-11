"""Deterministic synthetic smoke benchmark; contains no live malware samples.

Run from repository root with: python benchmarks/run_benchmark.py
These tiny indicators validate code paths, not real-world detection quality.
"""
import hashlib
import json
import platform
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import luna_guard as lg


def main():
    cases = [
        ("synthetic_xworm_markers", True,
         b"MZ" + b"\0" * 64 + b"mscoree.dll BSJB " + "<Xwormmm>".encode("utf-16le") + b" Xklog"),
        ("synthetic_powershell_loader", True,
         b"DownloadString FromBase64String -WindowStyle Hidden #" + b" " * 80),
        ("synthetic_hidden_powershell", True,
         b"-WindowStyle Hidden -ExecutionPolicy Bypass #" + b" " * 80),
        ("benign_text", False, b"Luna Guard synthetic benign document. " * 8),
        ("benign_pe_header", False, b"MZ" + b"\0" * 256),
        ("benign_script", False, b"Write-Output 'Hello, world'\n" * 8),
    ]
    rows = []
    started = time.perf_counter()
    old_app_dir, old_db_path = lg.APP_DIR, lg.DB_PATH
    with tempfile.TemporaryDirectory(prefix="luna-benchmark-") as temp:
        root = Path(temp)
        lg.APP_DIR, lg.DB_PATH = root / "data", root / "data" / "threats.db"
        try:
            con = lg.db()
            for name, expected, content in cases:
                path = root / (name + (".ps1" if "powershell" in name else ".exe" if "pe_" in name or "xworm" in name else ".txt"))
                path.write_bytes(content)
                began = time.perf_counter()
                severity, reasons, digest = lg.analyze(str(path), con)
                rows.append({
                    "case": name, "expected_positive": expected,
                    "detected": severity is not None, "severity": severity,
                    "correct": (severity is not None) == expected,
                    "sha256": digest or hashlib.sha256(content).hexdigest(),
                    "elapsed_ms": round((time.perf_counter() - began) * 1000, 3),
                    "reason_count": len(reasons),
                })
            con.close()
        finally:
            lg.APP_DIR, lg.DB_PATH = old_app_dir, old_db_path
    tp = sum(row["expected_positive"] and row["detected"] for row in rows)
    fp = sum(not row["expected_positive"] and row["detected"] for row in rows)
    fn = sum(row["expected_positive"] and not row["detected"] for row in rows)
    tn = sum(not row["expected_positive"] and not row["detected"] for row in rows)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and precision + recall else None)
    print(json.dumps({
        "benchmark": "Luna Guard synthetic smoke set",
        "scope_note": "Synthetic strings only; not an AV-TEST, VirusTotal, or real-world efficacy claim.",
        "python": platform.python_version(), "yara_available": bool(lg.yara_rules()),
        "dataset_version": "1", "count": len(rows), "TP": tp, "FP": fp,
        "FN": fn, "TN": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "accuracy_on_synthetic_set": round((tp + tn) / len(rows), 4),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        "cases": rows,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
