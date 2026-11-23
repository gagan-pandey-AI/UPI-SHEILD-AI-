"""Small dependency-free PDF builder for privacy-conscious scan reports."""

from __future__ import annotations

import re
import textwrap


def _pdf_text(value):
    """Return safe printable ASCII for the built-in PDF Helvetica font."""
    value = str(value or "").encode("ascii", "replace").decode("ascii")
    value = re.sub(r"[\x00-\x1f\x7f]", " ", value)
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(value, width=86):
    lines = textwrap.wrap(str(value or ""), width=width, break_long_words=True) or [""]
    return lines


def build_pdf(lines):
    """Build a minimal, multi-page PDF from already curated report lines."""
    pages = [lines[index:index + 48] for index in range(0, len(lines), 48)] or [[""]]
    objects = {}
    page_ids = [4 + index * 2 for index in range(len(pages))]
    content_ids = [item + 1 for item in page_ids]
    kids = " ".join(f"{item} 0 R" for item in page_ids)
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[2] = f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode("ascii")
    objects[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"

    for page_id, content_id, page_lines in zip(page_ids, content_ids, pages):
        commands = ["BT", "/F1 10 Tf", "50 750 Td", "14 TL"]
        for line in page_lines:
            commands.append(f"({_pdf_text(line)}) Tj")
            commands.append("T*")
        commands.append("ET")
        stream = "\n".join(commands).encode("ascii")
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode("ascii")
        objects[content_id] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode("ascii")
            + stream + b"\nendstream"
        )

    output = bytearray(b"%PDF-1.4\n%UPI Shield scan report\n")
    offsets = [0] * (max(objects) + 1)
    for object_id in range(1, max(objects) + 1):
        offsets[object_id] = len(output)
        output.extend(f"{object_id} 0 obj\n".encode("ascii"))
        output.extend(objects[object_id])
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def scan_report_lines(record, analysis):
    """Curate report contents without including the submitted message."""
    lines = [
        "UPI Shield AI - Scan Assessment Report",
        "",
        f"Scan date: {record['scan_date']}",
        f"Result category: {analysis.get('category') or 'General analysis'}",
        f"Recorded status: {record['status']}",
        f"Current heuristic risk level: {analysis.get('risk_level', 'UNKNOWN')}",
        f"Recorded heuristic risk score: {record['risk_score']}/100 (not a probability)",
        "",
        "Why this assessment?",
    ]
    indicators = analysis.get("observed_indicators") or []
    if indicators:
        for indicator in indicators:
            points = max(0, int(indicator.get("points") or 0))
            lines.extend(_wrap(f"- {indicator.get('reason', 'Indicator observed')} (+{points} heuristic points)"))
    else:
        reasons = analysis.get("reasons") or ["No major patterns matched; this does not establish safety."]
        for reason in reasons:
            lines.extend(_wrap(f"- {reason}"))
    lines.extend(["Points are heuristic weights, not calibrated probabilities.",
                  "Reasons are re-evaluated using the current rule set."])
    lines.extend(["", "URL structure findings (no URLs were visited; reputation was not checked):"])
    urls = analysis.get("urls") or []
    if not urls:
        lines.append("- No URL was found in the submitted scan text.")
    for item in urls:
        host = item.get("host") or "Unparsed host"
        indicators = item.get("indicators") or []
        if indicators:
            for indicator in indicators:
                lines.extend(_wrap(f"- Host {host}: {indicator.get('reason', 'Structural warning observed.')}"))
        else:
            lines.extend(_wrap(f"- Host {host}: no structural warning found; reputation was not checked."))
    lines.extend(["", "Safety recommendations:"])
    recommendations = analysis.get("safety_recommendations") or [
        "Verify payment, KYC, refund, and account requests through the official app or a known contact.",
        "Do not share passwords, PINs, or one-time passcodes in response to unsolicited requests.",
    ]
    for recommendation in recommendations:
        lines.extend(_wrap(f"- {recommendation}"))
    lines.extend(["", "Analysis limitations:"])
    for limitation in analysis.get("analysis_limitations") or [
        "This offline rule-based assessment is a heuristic aid, not proof of fraud or safety."
    ]:
        lines.extend(_wrap(f"- {limitation}"))
    lines.extend([
        "",
        "This offline rule-based assessment is a heuristic aid, not proof of fraud or safety.",
        "The submitted SMS text and account details are intentionally excluded from this report.",
    ])
    return lines


def create_scan_report(record, analysis):
    return build_pdf(scan_report_lines(record, analysis))
