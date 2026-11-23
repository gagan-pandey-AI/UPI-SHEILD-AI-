"""Run deterministic, offline evaluation on synthetic and UCI SMS fixtures."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import date
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from fraud_detector import analyze_sms
from qr_analyzer import analyze_qr_payload
from url_analyzer import analyze_urls


DATA_DIR = ROOT / "data"
FIXTURE_DIR = ROOT / "datasets"
DEFAULT_OUTPUT = ROOT / "results" / "latest.json"


def _metrics(rows):
    tp = tn = fp = fn = 0
    class_distribution = Counter()
    for actual, predicted in rows:
        class_distribution["positive" if actual else "negative"] += 1
        if actual and predicted:
            tp += 1
        elif actual:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    total = tp + tn + fp + fn

    def ratio(numerator, denominator):
        return round(numerator / denominator, 6) if denominator else None

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    return {
        "sample_count": total,
        "class_distribution": dict(class_distribution),
        "accuracy": ratio(tp + tn, total),
        "precision": precision,
        "recall": recall,
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "confusion_matrix": {
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
        },
        "false_positive_rate": ratio(fp, fp + tn),
        "false_negative_rate": ratio(fn, fn + tp),
    }


def _predict(record):
    task = record["task"]
    if task == "sms":
        result = analyze_sms(record["text"])
        return result["status"] in {"SUSPICIOUS", "FRAUD"}, result
    if task == "url":
        result = analyze_urls(record["text"])
        return any(item.get("indicators") for item in result["urls"]), result
    if task == "qr_payload":
        result = analyze_qr_payload(record["payload"])
        return result["risk_level"] in {"SUSPICIOUS", "MALICIOUS"}, result
    raise ValueError(f"Unsupported evaluation task: {task}")


def _read_fixtures():
    results = []
    for path in sorted(FIXTURE_DIR.glob("*.jsonl")):
        rows = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("data_origin") != "synthetic":
                raise ValueError(f"{path.name}:{line_number} is not marked synthetic.")
            if record.get("label") not in {"positive", "negative"}:
                raise ValueError(f"{path.name}:{line_number} has an invalid label.")
            prediction, detail = _predict(record)
            rows.append((record["label"] == "positive", prediction, record, detail))
        if rows:
            results.append((path.name, rows))
    return results


def _read_uci_sms(archive_path):
    with zipfile.ZipFile(archive_path) as archive:
        candidates = [name for name in archive.namelist() if name.endswith("SMSSpamCollection")]
        if len(candidates) != 1:
            raise ValueError("The UCI archive did not contain exactly one SMS collection file.")
        contents = archive.read(candidates[0]).decode("utf-8")
    rows = []
    for line_number, line in enumerate(contents.splitlines(), 1):
        if not line:
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2 or parts[0] not in {"ham", "spam"}:
            raise ValueError(f"Unexpected UCI row format at source line {line_number}.")
        label, message = parts
        prediction, _ = _predict({"task": "sms", "text": message})
        rows.append((label == "spam", prediction))
    return rows


def _summary(name, rows, *, data_origin, source, license_name, preprocessing):
    actual_prediction_pairs = [(actual, predicted) for actual, predicted, *_ in rows]
    return {
        "name": name,
        "data_origin": data_origin,
        "source": source,
        "license": license_name,
        "preprocessing": preprocessing,
        **_metrics(actual_prediction_pairs),
    }


def build_report(archive_path=None):
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    synthetic_meta = next(item for item in manifest["datasets"] if item["id"] == "synthetic_fixtures")
    uci_meta = next(item for item in manifest["datasets"] if item["id"] == "uci_sms_spam_collection")
    fixture_sets = _read_fixtures()
    reports = []
    grouped = {"sms": [], "url": [], "qr_payload": []}

    for filename, records in fixture_sets:
        reports.append(_summary(
            filename,
            records,
            data_origin="synthetic",
            source=synthetic_meta["source"],
            license_name=synthetic_meta["license"],
            preprocessing=synthetic_meta["preprocessing"],
        ))
        for _, _, record, _ in records:
            grouped[record["task"]].append((record["label"] == "positive", _predict(record)[0]))

    synthetic_groups = []
    for task, rows in grouped.items():
        if rows:
            synthetic_groups.append({
                "name": f"synthetic_{task}_combined",
                "data_origin": "synthetic",
                "source": synthetic_meta["source"],
                "license": synthetic_meta["license"],
                "preprocessing": "Combined authored fixtures for this input type; not representative field data.",
                **_metrics(rows),
            })

    archive_path = Path(archive_path or DATA_DIR / "uci-sms-spam-collection.zip")
    uci_rows = _read_uci_sms(archive_path)
    uci_report = _summary(
        "uci_sms_spam_collection",
        [(actual, predicted) for actual, predicted in uci_rows],
        data_origin="public_real_world_research_corpus",
        source=uci_meta["source"],
        license_name=uci_meta["license"],
        preprocessing=uci_meta["preprocessing"],
    )
    uci_report["collection_date"] = uci_meta["collection_date"]
    uci_report["source_doi"] = uci_meta["doi"]
    uci_report["source_url"] = uci_meta["source_url"]
    uci_report["sha256"] = hashlib.sha256(archive_path.read_bytes()).hexdigest()

    return {
        "evaluation_date": date.today().isoformat(),
        "method": manifest["method"],
        "limitations": [
            "Synthetic fixture metrics are rule-path sanity checks only; they are not real-world accuracy estimates.",
            "The UCI SMS corpus is old, English-heavy, and not representative of Indian UPI scams. Spam and fraud are not equivalent labels.",
            "URL and QR fixtures test structural warnings. Reputation providers are mocked by omission and are never contacted.",
            "Results measure this fixed rule set and threshold. They do not establish production-grade performance.",
        ],
        "synthetic_datasets": reports,
        "synthetic_combined_metrics": synthetic_groups,
        "public_dataset_metrics": [uci_report],
        "excluded_public_dataset": next(
            item for item in manifest["datasets"]
            if item["id"] == "uci_phishing_websites_excluded"
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uci-archive", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    report = build_report(args.uci_archive)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Evaluation written to {args.output}")
    for item in report["synthetic_datasets"] + report["synthetic_combined_metrics"] + report["public_dataset_metrics"]:
        print(
            f"{item['name']}: n={item['sample_count']} accuracy={item['accuracy']} "
            f"precision={item['precision']} recall={item['recall']} f1={item['f1']} "
            f"FPR={item['false_positive_rate']} FNR={item['false_negative_rate']}"
        )


if __name__ == "__main__":
    main()
