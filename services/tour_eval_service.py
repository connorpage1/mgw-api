"""
Tour evaluation helpers.
"""
from __future__ import annotations

import csv
import io
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from models import (
    db,
    TourEvalCriterion,
    TourEvalQuestion,
    TourEvalSection,
    TourEvaluation,
)

SCORE_VALUES = {
    "covered": 2,
    "partial": 1,
    "missed": 0,
}

DEFAULT_SECTIONS = [
    {
        "key": "arrival",
        "title": "Arrival and Setup",
        "items": [
            "Greeted the group warmly and set expectations for the tour.",
            "Started on time and confirmed everyone could hear clearly.",
        ],
    },
    {
        "key": "storytelling",
        "title": "Storytelling",
        "items": [
            "Explained the history of Mardi Gras World with confidence and accuracy.",
            "Connected props, floats, or costumes back to the story being told.",
        ],
    },
    {
        "key": "engagement",
        "title": "Guest Engagement",
        "items": [
            "Invited participation and responded clearly to guest questions.",
            "Maintained energy and kept the group moving at the right pace.",
        ],
    },
]

DEFAULT_CRITERIA = [
    "Professionalism",
    "Historical accuracy",
    "Guest engagement",
]


def _slugify(value):
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "item"


def _score_breakdown(item_scores):
    distribution = {"covered": 0, "partial": 0, "missed": 0}
    for item_score in item_scores:
        if item_score.score in distribution:
            distribution[item_score.score] += 1
    return distribution


def _score_summary(item_scores):
    distribution = _score_breakdown(item_scores)
    total_scores = sum(distribution.values())
    avg_score = None
    pct_covered = 0.0
    if total_scores:
        avg_score = round(
            (
                distribution["covered"] * SCORE_VALUES["covered"]
                + distribution["partial"] * SCORE_VALUES["partial"]
                + distribution["missed"] * SCORE_VALUES["missed"]
            )
            / total_scores,
            2,
        )
        pct_covered = round(distribution["covered"] * 100 / total_scores, 1)

    return distribution, total_scores, avg_score, pct_covered


def seed_default_tour_eval_catalog():
    """Seed the default evaluation catalog if it has not been created yet."""
    changed = False

    sections = {section.key: section for section in TourEvalSection.query.all()}
    for index, section_data in enumerate(DEFAULT_SECTIONS):
        section = sections.get(section_data["key"])
        if section is None:
            section = TourEvalSection(
                key=section_data["key"],
                title=section_data["title"],
                sort_order=index,
                is_active=True,
            )
            db.session.add(section)
            db.session.flush()
            sections[section.key] = section
            changed = True

    existing_questions = {
        (question.section_id, question.text.strip().lower()): question
        for question in TourEvalQuestion.query.all()
    }
    for section_data in DEFAULT_SECTIONS:
        section = sections[section_data["key"]]
        for index, text in enumerate(section_data["items"]):
            lookup_key = (section.id, text.strip().lower())
            if lookup_key in existing_questions:
                continue
            question = TourEvalQuestion(
                external_id=f"pending.{section.key}.{index}",
                section_id=section.id,
                text=text,
                sort_order=index,
                is_active=True,
            )
            db.session.add(question)
            db.session.flush()
            question.external_id = next_question_external_id(section.key, question.id)
            existing_questions[lookup_key] = question
            changed = True

    existing_criteria = {
        criterion.text.strip().lower(): criterion for criterion in TourEvalCriterion.query.all()
    }
    for index, text in enumerate(DEFAULT_CRITERIA):
        lookup_key = text.strip().lower()
        if lookup_key in existing_criteria:
            continue
        criterion = TourEvalCriterion(
            external_id=f"pending.criteria.{index}",
            text=text,
            sort_order=index,
            is_active=True,
        )
        db.session.add(criterion)
        db.session.flush()
        criterion.external_id = next_criteria_external_id(criterion.id)
        existing_criteria[lookup_key] = criterion
        changed = True

    if changed:
        db.session.commit()


def apply_tour_eval_filters(query, params):
    """Apply dashboard filters to a TourEvaluation query."""
    guide = (params.get("guide") or params.get("guide_name") or "").strip()
    evaluator = (params.get("evaluator") or "").strip()
    start_date = (params.get("start_date") or "").strip()
    end_date = (params.get("end_date") or "").strip()

    if guide:
        query = query.filter(TourEvaluation.guide_name == guide)
    if evaluator:
        query = query.filter(TourEvaluation.evaluator_name == evaluator)
    if start_date:
        query = query.filter(TourEvaluation.tour_date >= parse_tour_date(start_date))
    if end_date:
        end_dt = parse_tour_date(end_date)
        query = query.filter(TourEvaluation.tour_date < end_dt + timedelta(days=1))

    return query


def build_export_csv(evaluations):
    """Export evaluations in a compact CSV form."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "evaluation_id",
            "tour_date",
            "guide_name",
            "evaluator_name",
            "tour_number",
            "tour_time",
            "group_size",
            "avg_score",
            "pct_covered",
            "covered",
            "partial",
            "missed",
            "strengths",
            "deviations",
            "coaching_notes",
        ]
    )

    for evaluation in evaluations:
        distribution, _, avg_score, pct_covered = _score_summary(evaluation.item_scores)
        writer.writerow(
            [
                evaluation.id,
                evaluation.tour_date.isoformat() if evaluation.tour_date else "",
                evaluation.guide_name,
                evaluation.evaluator_name,
                evaluation.tour_number or "",
                evaluation.tour_time or "",
                evaluation.group_size or "",
                "" if avg_score is None else avg_score,
                pct_covered,
                distribution["covered"],
                distribution["partial"],
                distribution["missed"],
                evaluation.strengths,
                evaluation.deviations,
                evaluation.coaching_notes,
            ]
        )

    return output.getvalue()


def _escape_pdf_text(value):
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _render_basic_pdf(lines):
    y_position = 760
    content_lines = ["BT", "/F1 12 Tf", "14 TL"]
    for index, line in enumerate(lines):
        safe_line = _escape_pdf_text(line)
        if index == 0:
            content_lines.append(f"72 {y_position} Td")
        else:
            content_lines.append("0 -14 Td")
        content_lines.append(f"({safe_line}) Tj")
    content_lines.append("ET")

    stream = "\n".join(content_lines)
    stream_bytes = stream.encode("latin-1", "replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream_bytes) + stream_bytes + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = []
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_start}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(pdf)


def create_pdf_report(evaluation_payload):
    """Create a lightweight PDF summary without extra dependencies."""
    lines = [
        "Mardi Gras World Evaluation Report",
        f"Guide: {evaluation_payload.get('guide_name', '')}",
        f"Evaluator: {evaluation_payload.get('evaluator_name', '')}",
        f"Tour Date: {evaluation_payload.get('tour_date', '')}",
        f"Average Score: {evaluation_payload.get('avg_score', '')}",
        "",
    ]

    for item in evaluation_payload.get("item_scores", []):
        lines.append(f"[{item['score']}] {item['section_title']}: {item['item_text']}")

    if evaluation_payload.get("criteria_scores"):
        lines.append("")
        lines.append("Criteria")
        for item in evaluation_payload["criteria_scores"]:
            lines.append(f"[{item['score']}] {item['text']}")

    return _render_basic_pdf(lines)

def default_report_recipients():
    """Return default report recipients from configuration."""
    return normalize_recipients(os.environ.get("MGW_REPORT_DEFAULT_EMAILS", ""))


def get_catalog_lookup(include_inactive=True):
    """Return the catalog in both list and lookup forms."""
    section_query = TourEvalSection.query.order_by(TourEvalSection.sort_order, TourEvalSection.id)
    if not include_inactive:
        section_query = section_query.filter(TourEvalSection.is_active.is_(True))
    sections = section_query.all()

    section_ids = [section.id for section in sections]
    question_lookup = {}
    section_items = defaultdict(list)
    if section_ids:
        question_query = TourEvalQuestion.query.filter(TourEvalQuestion.section_id.in_(section_ids))
        if not include_inactive:
            question_query = question_query.filter(TourEvalQuestion.is_active.is_(True))
        questions = question_query.order_by(TourEvalQuestion.sort_order, TourEvalQuestion.id).all()
        for question in questions:
            section = next(section for section in sections if section.id == question.section_id)
            item_payload = {
                "id": question.external_id,
                "external_id": question.external_id,
                "text": question.text,
                "section_key": section.key,
                "section_title": section.title,
                "sort_order": question.sort_order,
            }
            question_lookup[question.external_id] = item_payload
            section_items[question.section_id].append(item_payload)

    criteria_query = TourEvalCriterion.query.order_by(TourEvalCriterion.sort_order, TourEvalCriterion.id)
    if not include_inactive:
        criteria_query = criteria_query.filter(TourEvalCriterion.is_active.is_(True))
    criteria = criteria_query.all()

    criteria_lookup = {
        criterion.external_id: {
            "id": criterion.external_id,
            "external_id": criterion.external_id,
            "text": criterion.text,
            "sort_order": criterion.sort_order,
        }
        for criterion in criteria
    }

    return {
        "sections": [
            {
                "id": section.id,
                "key": section.key,
                "title": section.title,
                "sort_order": section.sort_order,
                "items": section_items.get(section.id, []),
            }
            for section in sections
        ],
        "questions": question_lookup,
        "criteria": criteria_lookup,
        "criteria_list": list(criteria_lookup.values()),
    }

def get_coaching_threshold():
    """Return the coaching threshold as a float."""
    return float(os.environ.get("MGW_COACHING_THRESHOLD", "1.3"))


def normalize_recipients(raw):
    """Normalize a list or CSV string of email recipients."""
    if not raw:
        return []

    if isinstance(raw, str):
        candidates = [item.strip() for item in raw.split(",")]
    else:
        candidates = [str(item).strip() for item in raw]

    recipients = []
    seen = set()
    for candidate in candidates:
        if not candidate or "@" not in candidate:
            continue
        lowered = candidate.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        recipients.append(candidate)

    return recipients


def next_criteria_external_id(criteria_id):
    """Build a stable external id for a criterion."""
    return f"CRITERION-{int(criteria_id):03d}"


def next_question_external_id(section_key, question_id):
    """Build a stable external id for a question."""
    return f"{_slugify(section_key).upper()}-{int(question_id):03d}"


def parse_tour_date(raw_value):
    """Parse a tour date from YYYY-MM-DD or ISO-8601."""
    if raw_value is None:
        raise ValueError("tour_date is required")

    value = str(raw_value).strip()
    if not value:
        raise ValueError("tour_date is required")

    if len(value) == 10:
        return datetime.strptime(value, "%Y-%m-%d")

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed

def recent_evaluation_cutoff():
    """Return the trailing 30-day cutoff used by the dashboard."""
    return datetime.utcnow() - timedelta(days=30)


def report_filename(evaluation_payload):
    """Generate a stable PDF filename for an evaluation."""
    guide_name = _slugify(evaluation_payload.get("guide_name", "guide"))
    tour_date = _slugify(evaluation_payload.get("tour_date", datetime.utcnow().date().isoformat()))
    return f"mgw-evaluation-{guide_name}-{tour_date}.pdf"


def serialize_evaluation_detail(evaluation):
    """Serialize an evaluation with all score details."""
    distribution, total_scores, avg_score, pct_covered = _score_summary(evaluation.item_scores)
    return {
        "id": evaluation.id,
        "guide_name": evaluation.guide_name,
        "evaluator_name": evaluation.evaluator_name,
        "tour_number": evaluation.tour_number,
        "tour_time": evaluation.tour_time,
        "tour_date": evaluation.tour_date.date().isoformat() if evaluation.tour_date else None,
        "group_size": evaluation.group_size,
        "strengths": evaluation.strengths,
        "deviations": evaluation.deviations,
        "coaching_notes": evaluation.coaching_notes,
        "created_at": evaluation.created_at.isoformat() if evaluation.created_at else None,
        "avg_score": avg_score,
        "pct_covered": pct_covered,
        "score_distribution": distribution,
        "total_scores": total_scores,
        "item_scores": [
            {
                "item_id": item.item_id,
                "section_key": item.section_key,
                "section_title": item.section_title,
                "item_text": item.item_text,
                "score": item.score,
                "notes": item.section_notes,
            }
            for item in evaluation.item_scores
        ],
        "criteria_scores": [
            {
                "criteria_id": item.criteria_id,
                "text": item.criteria_text,
                "score": item.score,
            }
            for item in evaluation.criteria_scores
        ],
    }


def serialize_evaluation_row(evaluation):
    """Serialize an evaluation for list views."""
    distribution, total_scores, avg_score, pct_covered = _score_summary(evaluation.item_scores)
    return {
        "id": evaluation.id,
        "guide_name": evaluation.guide_name,
        "evaluator_name": evaluation.evaluator_name,
        "tour_date": evaluation.tour_date.isoformat() if evaluation.tour_date else None,
        "created_at": evaluation.created_at.isoformat() if evaluation.created_at else None,
        "avg_score": avg_score,
        "pct_covered": pct_covered,
        "total_scores": total_scores,
        "score_distribution": distribution,
    }


def serialize_tour_eval_catalog(include_inactive=True):
    """Serialize the catalog for the frontend."""
    catalog = get_catalog_lookup(include_inactive=include_inactive)
    return {
        "sections": catalog["sections"],
        "criteria": catalog["criteria_list"],
    }
