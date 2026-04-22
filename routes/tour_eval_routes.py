"""
Routes for the MGW tour evaluation domain.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, request
from sqlalchemy.orm import selectinload

from models import (
    db,
    TourEvalCriterion,
    TourEvalQuestion,
    TourEvalSection,
    TourEvaluation,
    TourEvaluationCriteriaScore,
    TourEvaluationItemScore,
)
from services.email_service import EmailAttachment, email_service
from services.oauth2_service import require_oauth2_if_enabled
from services.tour_eval_service import (
    SCORE_VALUES,
    apply_tour_eval_filters,
    build_export_csv,
    create_pdf_report,
    default_report_recipients,
    get_catalog_lookup,
    get_coaching_threshold,
    normalize_recipients,
    next_criteria_external_id,
    next_question_external_id,
    parse_tour_date,
    recent_evaluation_cutoff,
    report_filename,
    seed_default_tour_eval_catalog,
    serialize_evaluation_detail,
    serialize_evaluation_row,
    serialize_tour_eval_catalog,
)
from utils.logger import logger


tour_eval_bp = Blueprint("tour_eval", __name__)
tour_eval_reports_required = require_oauth2_if_enabled(
    "TOUR_EVAL_REPORTS_AUTH_REQUIRED", ["admin", "admin_read"]
)
tour_eval_admin_read_required = require_oauth2_if_enabled(
    "TOUR_EVAL_ADMIN_AUTH_REQUIRED", ["admin", "admin_read"]
)
tour_eval_admin_write_required = require_oauth2_if_enabled(
    "TOUR_EVAL_ADMIN_AUTH_REQUIRED", ["admin"]
)


def _merge_recipients(explicit_recipients) -> list[str]:
    recipients = normalize_recipients(explicit_recipients)
    seen = {email.lower() for email in recipients}
    for email in default_report_recipients():
        if email.lower() in seen:
            continue
        seen.add(email.lower())
        recipients.append(email)
    return recipients


def _send_evaluation_report_email(evaluation_payload: dict, recipients: list[str]) -> dict:
    pdf_bytes = create_pdf_report(evaluation_payload)
    filename = report_filename(evaluation_payload)
    subject = (
        f"MGW evaluation report — {evaluation_payload['guide_name']} — "
        f"{evaluation_payload['tour_date']}"
    )
    text_content = (
        f"Attached is the Mardi Gras World tour evaluation report for "
        f"{evaluation_payload['guide_name']} from {evaluation_payload['tour_date']}."
    )
    html_content = (
        "<p>Attached is the Mardi Gras World tour evaluation report for "
        f"<strong>{evaluation_payload['guide_name']}</strong> from "
        f"<strong>{evaluation_payload['tour_date']}</strong>.</p>"
    )
    return email_service.send_email(
        recipients=recipients,
        subject=subject,
        text_content=text_content,
        html_content=html_content,
        attachments=[
            EmailAttachment(
                filename=filename,
                content=pdf_bytes,
                content_type="application/pdf",
            )
        ],
    )


def _load_evaluation(eval_id: str) -> TourEvaluation | None:
    return (
        TourEvaluation.query.options(
            selectinload(TourEvaluation.item_scores),
            selectinload(TourEvaluation.criteria_scores),
        )
        .filter(TourEvaluation.id == eval_id)
        .first()
    )


@tour_eval_bp.route("/talking-points")
def get_talking_points():
    """Return the active evaluation catalog for the frontend."""
    seed_default_tour_eval_catalog()
    return jsonify(serialize_tour_eval_catalog(include_inactive=False))


@tour_eval_bp.route("/evaluations", methods=["POST"])
def submit_evaluation():
    """Submit a new guide evaluation."""
    seed_default_tour_eval_catalog()
    data = request.get_json(force=True) or {}

    required = ["guide_name", "evaluator_name", "tour_date", "item_scores"]
    missing = [field for field in required if not data.get(field)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    catalog = get_catalog_lookup(include_inactive=False)
    evaluation = TourEvaluation(
        guide_name=data["guide_name"].strip(),
        evaluator_name=data["evaluator_name"].strip(),
        tour_number=(data.get("tour_number") or "").strip() or None,
        tour_time=(data.get("tour_time") or "").strip() or None,
        tour_date=parse_tour_date(data["tour_date"]),
        group_size=int(data["group_size"]) if data.get("group_size") else None,
        strengths=data.get("strengths") or "",
        deviations=data.get("deviations") or "",
        coaching_notes=data.get("coaching_notes") or "",
    )

    db.session.add(evaluation)
    db.session.flush()

    valid_item_scores = 0
    for item_id, raw_score in (data.get("item_scores") or {}).items():
        question_meta = catalog["questions"].get(item_id)
        if not question_meta:
            continue
        score = raw_score.get("score") if isinstance(raw_score, dict) else raw_score
        if score not in SCORE_VALUES:
            continue
        notes = raw_score.get("notes", "") if isinstance(raw_score, dict) else ""
        db.session.add(
            TourEvaluationItemScore(
                evaluation_id=evaluation.id,
                item_id=item_id,
                section_key=question_meta["section_key"],
                section_title=question_meta["section_title"],
                item_text=question_meta["text"],
                score=score,
                section_notes=notes,
            )
        )
        valid_item_scores += 1

    for criteria_id, score in (data.get("criteria_scores") or {}).items():
        criteria_meta = catalog["criteria"].get(criteria_id)
        if not criteria_meta or score not in SCORE_VALUES:
            continue
        db.session.add(
            TourEvaluationCriteriaScore(
                evaluation_id=evaluation.id,
                criteria_id=criteria_id,
                criteria_text=criteria_meta["text"],
                score=score,
            )
        )

    if valid_item_scores == 0:
        db.session.rollback()
        return jsonify({"error": "At least one valid talking-point score is required."}), 400

    try:
        db.session.commit()
    except Exception as exc:
        logger.error("Error saving evaluation: %s", exc)
        db.session.rollback()
        return jsonify({"error": "Failed to save evaluation"}), 500

    evaluation = _load_evaluation(evaluation.id)
    payload = serialize_evaluation_detail(evaluation)
    response = {
        "id": evaluation.id,
        "created_at": evaluation.created_at.isoformat() if evaluation.created_at else None,
    }

    recipients = _merge_recipients(data.get("report_recipients"))
    if recipients:
        try:
            response["report_email"] = _send_evaluation_report_email(payload, recipients)
        except Exception as exc:
            response["report_email"] = {
                "sent": False,
                "recipients": recipients,
                "error": str(exc),
            }

    return jsonify(response), 201


@tour_eval_bp.route("/evaluations")
@tour_eval_reports_required
def list_evaluations():
    """List evaluations for dashboard/history views."""
    query = TourEvaluation.query.options(selectinload(TourEvaluation.item_scores))
    query = apply_tour_eval_filters(query, request.args)
    evaluations = query.order_by(TourEvaluation.tour_date.desc(), TourEvaluation.created_at.desc()).all()
    return jsonify([serialize_evaluation_row(evaluation) for evaluation in evaluations])


@tour_eval_bp.route("/evaluations/<eval_id>")
@tour_eval_reports_required
def get_evaluation(eval_id):
    """Get a single evaluation with all score details."""
    evaluation = _load_evaluation(eval_id)
    if not evaluation:
        return jsonify({"error": "Not found"}), 404
    return jsonify(serialize_evaluation_detail(evaluation))


@tour_eval_bp.route("/evaluations/<eval_id>/pdf")
@tour_eval_reports_required
def get_evaluation_pdf(eval_id):
    """Generate a printable PDF report."""
    evaluation = _load_evaluation(eval_id)
    if not evaluation:
        return jsonify({"error": "Not found"}), 404

    payload = serialize_evaluation_detail(evaluation)
    pdf_bytes = create_pdf_report(payload)
    disposition = "attachment" if request.args.get("download") == "1" else "inline"
    filename = report_filename(payload)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"{disposition}; filename={filename}"},
    )


@tour_eval_bp.route("/evaluations/<eval_id>/email", methods=["POST"])
@tour_eval_reports_required
def email_evaluation_pdf(eval_id):
    """Email a PDF report for a completed evaluation."""
    evaluation = _load_evaluation(eval_id)
    if not evaluation:
        return jsonify({"error": "Not found"}), 404

    data = request.get_json(silent=True) or {}
    explicit_recipients = normalize_recipients(data.get("recipients"))
    recipients = explicit_recipients or default_report_recipients()
    if not recipients:
        return jsonify(
            {
                "error": (
                    "No recipient emails provided and no default report recipients configured."
                )
            }
        ), 400

    payload = serialize_evaluation_detail(evaluation)
    try:
        result = _send_evaluation_report_email(payload, recipients)
    except Exception as exc:
        logger.error("Evaluation email send failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    return jsonify(result)


@tour_eval_bp.route("/dashboard/summary")
@tour_eval_reports_required
def dashboard_summary():
    """Return top-line evaluation stats."""
    query = TourEvaluation.query.options(selectinload(TourEvaluation.item_scores))
    evaluations = apply_tour_eval_filters(query, request.args).all()
    total_evaluations = len(evaluations)
    if total_evaluations == 0:
        return jsonify(
            {
                "total_evaluations": 0,
                "unique_guides": 0,
                "avg_score": None,
                "score_distribution": {"covered": 0, "partial": 0, "missed": 0},
                "recent_count_30d": 0,
            }
        )

    distribution = {"covered": 0, "partial": 0, "missed": 0}
    unique_guides = set()
    recent_cutoff = recent_evaluation_cutoff()
    recent_count = 0
    for evaluation in evaluations:
        unique_guides.add(evaluation.guide_name)
        if evaluation.tour_date >= recent_cutoff:
            recent_count += 1
        for item_score in evaluation.item_scores:
            if item_score.score in distribution:
                distribution[item_score.score] += 1

    total_scores = sum(distribution.values())
    avg_score = None
    if total_scores:
        avg_score = round(
            (distribution["covered"] * 2 + distribution["partial"]) / total_scores,
            2,
        )

    return jsonify(
        {
            "total_evaluations": total_evaluations,
            "unique_guides": len(unique_guides),
            "avg_score": avg_score,
            "score_distribution": distribution,
            "recent_count_30d": recent_count,
        }
    )


@tour_eval_bp.route("/dashboard/guides")
@tour_eval_reports_required
def dashboard_guides():
    """Return the per-guide leaderboard."""
    query = TourEvaluation.query.options(selectinload(TourEvaluation.item_scores))
    evaluations = apply_tour_eval_filters(query, request.args).all()
    grouped = defaultdict(
        lambda: {
            "guide_name": "",
            "eval_count": 0,
            "last_evaluated": None,
            "n_covered": 0,
            "n_partial": 0,
            "n_missed": 0,
        }
    )

    for evaluation in evaluations:
        entry = grouped[evaluation.guide_name]
        entry["guide_name"] = evaluation.guide_name
        entry["eval_count"] += 1
        if entry["last_evaluated"] is None or evaluation.tour_date > entry["last_evaluated"]:
            entry["last_evaluated"] = evaluation.tour_date
        for item_score in evaluation.item_scores:
            if item_score.score == "covered":
                entry["n_covered"] += 1
            elif item_score.score == "partial":
                entry["n_partial"] += 1
            elif item_score.score == "missed":
                entry["n_missed"] += 1

    threshold = get_coaching_threshold()
    result = []
    for entry in grouped.values():
        total_scores = entry["n_covered"] + entry["n_partial"] + entry["n_missed"]
        avg_score = (
            round((entry["n_covered"] * 2 + entry["n_partial"]) / total_scores, 2)
            if total_scores
            else 0
        )
        pct_covered = round(entry["n_covered"] * 100 / total_scores, 1) if total_scores else 0
        result.append(
            {
                "guide_name": entry["guide_name"],
                "eval_count": entry["eval_count"],
                "last_evaluated": entry["last_evaluated"].isoformat()
                if entry["last_evaluated"]
                else None,
                "avg_score": avg_score,
                "pct_covered": pct_covered,
                "n_covered": entry["n_covered"],
                "n_partial": entry["n_partial"],
                "n_missed": entry["n_missed"],
                "needs_coaching": avg_score < threshold,
            }
        )

    result.sort(key=lambda item: item["avg_score"], reverse=True)
    return jsonify(result)


@tour_eval_bp.route("/dashboard/guide/<path:guide_name>")
@tour_eval_reports_required
def dashboard_guide_detail(guide_name):
    """Return timeline and section breakdown for a specific guide."""
    catalog = get_catalog_lookup(include_inactive=True)
    evaluations = (
        TourEvaluation.query.options(selectinload(TourEvaluation.item_scores))
        .filter(TourEvaluation.guide_name == guide_name)
        .order_by(TourEvaluation.tour_date, TourEvaluation.created_at)
        .all()
    )

    if not evaluations:
        return jsonify({"guide_name": guide_name, "timeline": [], "section_breakdown": []})

    timeline = []
    section_totals = defaultdict(lambda: {"title": "", "covered": 0, "partial": 0, "missed": 0})
    for evaluation in evaluations:
        distribution = {"covered": 0, "partial": 0, "missed": 0}
        for item_score in evaluation.item_scores:
            if item_score.score in distribution:
                distribution[item_score.score] += 1
                section_totals[item_score.section_key]["title"] = item_score.section_title
                section_totals[item_score.section_key][item_score.score] += 1

        total_scores = sum(distribution.values())
        avg_score = (
            round((distribution["covered"] * 2 + distribution["partial"]) / total_scores, 2)
            if total_scores
            else 0
        )
        timeline.append(
            {
                "evaluation_id": evaluation.id,
                "date": evaluation.tour_date.isoformat(),
                "evaluator": evaluation.evaluator_name,
                "avg_score": avg_score,
                "pct_covered": round(distribution["covered"] * 100 / total_scores, 1)
                if total_scores
                else 0,
            }
        )

    section_order = {section["key"]: index for index, section in enumerate(catalog["sections"])}
    section_breakdown = []
    for section_key, values in section_totals.items():
        total_scores = values["covered"] + values["partial"] + values["missed"]
        if total_scores == 0:
            continue
        section_breakdown.append(
            {
                "section_key": section_key,
                "section_title": values["title"] or section_key,
                "avg_score": round((values["covered"] * 2 + values["partial"]) / total_scores, 2),
                "n_covered": values["covered"],
                "n_partial": values["partial"],
                "n_missed": values["missed"],
            }
        )

    section_breakdown.sort(
        key=lambda item: (
            section_order.get(item["section_key"], 9999),
            item["section_title"].lower(),
        )
    )

    return jsonify(
        {
            "guide_name": guide_name,
            "timeline": timeline,
            "section_breakdown": section_breakdown,
        }
    )


@tour_eval_bp.route("/dashboard/missed-items")
@tour_eval_reports_required
def dashboard_missed_items():
    """Return team-wide missed/partial coverage hotspots."""
    query = TourEvaluation.query.options(selectinload(TourEvaluation.item_scores))
    evaluations = apply_tour_eval_filters(query, request.args).all()
    if not evaluations:
        return jsonify([])

    item_totals = defaultdict(
        lambda: {
            "section_title": "",
            "section_key": "",
            "text": "",
            "n_covered": 0,
            "n_partial": 0,
            "n_missed": 0,
        }
    )

    for evaluation in evaluations:
        for item_score in evaluation.item_scores:
            entry = item_totals[item_score.item_id]
            entry["section_title"] = item_score.section_title
            entry["section_key"] = item_score.section_key
            entry["text"] = item_score.item_text
            if item_score.score == "covered":
                entry["n_covered"] += 1
            elif item_score.score == "partial":
                entry["n_partial"] += 1
            elif item_score.score == "missed":
                entry["n_missed"] += 1

    result = []
    section_filter = request.args.get("section")
    for item_id, values in item_totals.items():
        if section_filter and values["section_key"] != section_filter:
            continue
        total_scores = values["n_covered"] + values["n_partial"] + values["n_missed"]
        miss_rate = (
            round((values["n_missed"] + values["n_partial"] * 0.5) * 100 / total_scores, 1)
            if total_scores
            else 0
        )
        result.append(
            {
                "item_id": item_id,
                "section_title": values["section_title"],
                "section_key": values["section_key"],
                "text": values["text"],
                "n_covered": values["n_covered"],
                "n_partial": values["n_partial"],
                "n_missed": values["n_missed"],
                "miss_rate": miss_rate,
                "total": total_scores,
            }
        )

    result.sort(key=lambda item: item["miss_rate"], reverse=True)
    return jsonify(result)


@tour_eval_bp.route("/dashboard/coaching")
@tour_eval_reports_required
def dashboard_coaching():
    """Return guides that fall below the coaching threshold."""
    evaluations = TourEvaluation.query.options(selectinload(TourEvaluation.item_scores)).all()
    grouped = defaultdict(
        lambda: {
            "guide_name": "",
            "covered": 0,
            "partial": 0,
            "missed": 0,
            "eval_count": 0,
            "last_evaluated": None,
        }
    )
    for evaluation in evaluations:
        entry = grouped[evaluation.guide_name]
        entry["guide_name"] = evaluation.guide_name
        entry["eval_count"] += 1
        if entry["last_evaluated"] is None or evaluation.tour_date > entry["last_evaluated"]:
            entry["last_evaluated"] = evaluation.tour_date
        for item_score in evaluation.item_scores:
            if item_score.score == "covered":
                entry["covered"] += 1
            elif item_score.score == "partial":
                entry["partial"] += 1
            elif item_score.score == "missed":
                entry["missed"] += 1

    threshold = get_coaching_threshold()
    flagged = []
    for entry in grouped.values():
        total_scores = entry["covered"] + entry["partial"] + entry["missed"]
        if total_scores == 0:
            continue
        avg_score = round((entry["covered"] * 2 + entry["partial"]) / total_scores, 2)
        if avg_score < threshold:
            flagged.append(
                {
                    "guide_name": entry["guide_name"],
                    "avg_score": avg_score,
                    "eval_count": entry["eval_count"],
                    "last_evaluated": entry["last_evaluated"].isoformat()
                    if entry["last_evaluated"]
                    else None,
                    "threshold": threshold,
                }
            )

    flagged.sort(key=lambda item: item["avg_score"])
    return jsonify(flagged)


@tour_eval_bp.route("/filters")
@tour_eval_reports_required
def filters():
    """Return filter dropdown options for the dashboard."""
    guide_rows = (
        db.session.query(TourEvaluation.guide_name)
        .distinct()
        .order_by(TourEvaluation.guide_name)
        .all()
    )
    evaluator_rows = (
        db.session.query(TourEvaluation.evaluator_name)
        .distinct()
        .order_by(TourEvaluation.evaluator_name)
        .all()
    )
    catalog = serialize_tour_eval_catalog(include_inactive=False)
    return jsonify(
        {
            "guides": [row[0] for row in guide_rows],
            "evaluators": [row[0] for row in evaluator_rows],
            "sections": [{"key": section["key"], "title": section["title"]} for section in catalog["sections"]],
        }
    )


@tour_eval_bp.route("/export/csv")
@tour_eval_reports_required
def export_csv():
    """Export a filtered evaluation set as CSV."""
    query = TourEvaluation.query.options(
        selectinload(TourEvaluation.item_scores),
        selectinload(TourEvaluation.criteria_scores),
    )
    evaluations = apply_tour_eval_filters(query, request.args).order_by(
        TourEvaluation.tour_date.desc(),
        TourEvaluation.created_at.desc(),
    ).all()
    csv_payload = build_export_csv(evaluations)
    filename = f"mgw_evaluations_{datetime.now(timezone.utc).date().isoformat()}.csv"
    return Response(
        csv_payload,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@tour_eval_bp.route("/admin/sections")
@tour_eval_admin_read_required
def get_admin_sections():
    """List sections for the admin UI."""
    sections = (
        TourEvalSection.query.order_by(TourEvalSection.sort_order, TourEvalSection.id).all()
    )
    return jsonify(
        [
            {
                "id": section.id,
                "key": section.key,
                "title": section.title,
                "sort_order": section.sort_order,
                "is_active": section.is_active,
            }
            for section in sections
        ]
    )


@tour_eval_bp.route("/admin/sections", methods=["POST"])
@tour_eval_admin_write_required
def create_section():
    """Create a new evaluation section."""
    data = request.get_json(force=True) or {}
    required = ["key", "title"]
    missing = [field for field in required if not data.get(field)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    existing = TourEvalSection.query.filter(TourEvalSection.key == data["key"].strip()).first()
    if existing:
        return jsonify({"error": "Section key already exists"}), 400

    max_sort_order = db.session.query(db.func.max(TourEvalSection.sort_order)).scalar()
    section = TourEvalSection(
        key=data["key"].strip(),
        title=data["title"].strip(),
        sort_order=(max_sort_order + 1) if max_sort_order is not None else 0,
        is_active=bool(data.get("is_active", True)),
    )
    db.session.add(section)
    db.session.commit()
    return jsonify({"success": True, "id": section.id}), 201


@tour_eval_bp.route("/admin/sections/<int:section_id>", methods=["PUT"])
@tour_eval_admin_write_required
def update_section(section_id):
    """Update section metadata."""
    section = TourEvalSection.query.get(section_id)
    if not section:
        return jsonify({"error": "Section not found"}), 404

    data = request.get_json(force=True) or {}
    if "title" in data:
        section.title = data["title"].strip()
    if "sort_order" in data:
        section.sort_order = int(data["sort_order"])
    if "is_active" in data:
        section.is_active = bool(data["is_active"])

    db.session.commit()
    return jsonify({"success": True})


@tour_eval_bp.route("/admin/sections/<int:section_id>", methods=["DELETE"])
@tour_eval_admin_write_required
def delete_section(section_id):
    """Delete a section and its questions."""
    section = TourEvalSection.query.get(section_id)
    if not section:
        return jsonify({"error": "Section not found"}), 404

    db.session.delete(section)
    db.session.commit()
    return jsonify({"success": True})


@tour_eval_bp.route("/admin/sections/<int:section_id>/questions")
@tour_eval_admin_read_required
def get_section_questions(section_id):
    """List questions for a section."""
    questions = (
        TourEvalQuestion.query.filter(TourEvalQuestion.section_id == section_id)
        .order_by(TourEvalQuestion.sort_order, TourEvalQuestion.id)
        .all()
    )
    return jsonify(
        [
            {
                "id": question.id,
                "external_id": question.external_id,
                "text": question.text,
                "sort_order": question.sort_order,
                "is_active": question.is_active,
            }
            for question in questions
        ]
    )


@tour_eval_bp.route("/admin/sections/<int:section_id>/questions", methods=["POST"])
@tour_eval_admin_write_required
def create_question(section_id):
    """Create a new question within a section."""
    section = TourEvalSection.query.get(section_id)
    if not section:
        return jsonify({"error": "Section not found"}), 404

    data = request.get_json(force=True) or {}
    if not data.get("text"):
        return jsonify({"error": "Missing text field"}), 400

    max_sort_order = (
        db.session.query(db.func.max(TourEvalQuestion.sort_order))
        .filter(TourEvalQuestion.section_id == section_id)
        .scalar()
    )
    question = TourEvalQuestion(
        external_id=f"pending.{datetime.now(timezone.utc).timestamp()}",
        section_id=section_id,
        text=data["text"].strip(),
        sort_order=(max_sort_order + 1) if max_sort_order is not None else 0,
        is_active=bool(data.get("is_active", True)),
    )
    db.session.add(question)
    db.session.flush()
    question.external_id = next_question_external_id(section.key, question.id)
    db.session.commit()
    return jsonify({"success": True, "id": question.id, "external_id": question.external_id}), 201


@tour_eval_bp.route("/admin/questions/<int:question_id>", methods=["PUT"])
@tour_eval_admin_write_required
def update_question(question_id):
    """Update question text, order, or active state."""
    question = TourEvalQuestion.query.get(question_id)
    if not question:
        return jsonify({"error": "Question not found"}), 404

    data = request.get_json(force=True) or {}
    if "text" in data:
        question.text = data["text"].strip()
    if "sort_order" in data:
        question.sort_order = int(data["sort_order"])
    if "is_active" in data:
        question.is_active = bool(data["is_active"])

    db.session.commit()
    return jsonify({"success": True})


@tour_eval_bp.route("/admin/questions/<int:question_id>", methods=["DELETE"])
@tour_eval_admin_write_required
def delete_question(question_id):
    """Delete a question from the catalog."""
    question = TourEvalQuestion.query.get(question_id)
    if not question:
        return jsonify({"error": "Question not found"}), 404

    db.session.delete(question)
    db.session.commit()
    return jsonify({"success": True})


@tour_eval_bp.route("/admin/criteria")
@tour_eval_admin_read_required
def get_admin_criteria():
    """List criteria for the admin UI."""
    criteria = (
        TourEvalCriterion.query.order_by(TourEvalCriterion.sort_order, TourEvalCriterion.id).all()
    )
    return jsonify(
        [
            {
                "id": criterion.id,
                "external_id": criterion.external_id,
                "text": criterion.text,
                "sort_order": criterion.sort_order,
                "is_active": criterion.is_active,
            }
            for criterion in criteria
        ]
    )


@tour_eval_bp.route("/admin/criteria", methods=["POST"])
@tour_eval_admin_write_required
def create_criteria():
    """Create a new performance criterion."""
    data = request.get_json(force=True) or {}
    if not data.get("text"):
        return jsonify({"error": "Missing text field"}), 400

    max_sort_order = db.session.query(db.func.max(TourEvalCriterion.sort_order)).scalar()
    criterion = TourEvalCriterion(
        external_id=f"pending.{datetime.now(timezone.utc).timestamp()}",
        text=data["text"].strip(),
        sort_order=(max_sort_order + 1) if max_sort_order is not None else 0,
        is_active=bool(data.get("is_active", True)),
    )
    db.session.add(criterion)
    db.session.flush()
    criterion.external_id = next_criteria_external_id(criterion.id)
    db.session.commit()
    return jsonify({"success": True, "id": criterion.id, "external_id": criterion.external_id}), 201


@tour_eval_bp.route("/admin/criteria/<int:criteria_id>", methods=["PUT"])
@tour_eval_admin_write_required
def update_criteria(criteria_id):
    """Update criterion text, order, or active state."""
    criterion = TourEvalCriterion.query.get(criteria_id)
    if not criterion:
        return jsonify({"error": "Criteria not found"}), 404

    data = request.get_json(force=True) or {}
    if "text" in data:
        criterion.text = data["text"].strip()
    if "sort_order" in data:
        criterion.sort_order = int(data["sort_order"])
    if "is_active" in data:
        criterion.is_active = bool(data["is_active"])

    db.session.commit()
    return jsonify({"success": True})


@tour_eval_bp.route("/admin/criteria/<int:criteria_id>", methods=["DELETE"])
@tour_eval_admin_write_required
def delete_criteria(criteria_id):
    """Delete a performance criterion."""
    criterion = TourEvalCriterion.query.get(criteria_id)
    if not criterion:
        return jsonify({"error": "Criteria not found"}), 404

    db.session.delete(criterion)
    db.session.commit()
    return jsonify({"success": True})
