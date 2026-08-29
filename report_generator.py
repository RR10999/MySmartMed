"""
report_generator.py
--------------------
Report Generation Module (Section IV-C: Weekly Report, IV-E: Inter-Visit
Patient Summary Report).

Both reports are built entirely on-device: the relevant fields are
decrypted in-memory only for the duration of PDF rendering and the
plaintext values are never written to disk except inside the
generated PDF itself, which the paper describes as an intentional,
nurse-initiated export ("Sensitive attributes are decrypted
in-memory exclusively for the report generation and are never
written to external storage in plaintext" [outside of the report]).
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="MSMTitle", fontSize=18, leading=22,
                               spaceAfter=6, textColor=colors.HexColor("#1a3c6e")))
    styles.add(ParagraphStyle(name="MSMSubtitle", fontSize=11, leading=14,
                               textColor=colors.grey, spaceAfter=14))
    styles.add(ParagraphStyle(name="MSMHeading", fontSize=13, leading=16,
                               spaceBefore=12, spaceAfter=6,
                               textColor=colors.HexColor("#1a3c6e")))
    return styles


def _table(data, col_widths=None):
    t = Table(data, colWidths=col_widths, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a3c6e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


def generate_weekly_report(patient_info: dict, medicines: list, compliance_summary: list,
                            refills: list, last_visit: dict, next_visit: dict) -> bytes:
    """
    Weekly Report: communication tool between the Family and the caretaker
    (Section IV-C). Summarises current prescribed medicines, doses taken /
    missed, remaining quantity, refill status, and next doctor's visit.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                             topMargin=20 * mm, bottomMargin=18 * mm,
                             leftMargin=18 * mm, rightMargin=18 * mm)
    styles = _styles()
    story = []

    story.append(Paragraph("MySmartMed — Weekly Adherence Report", styles["MSMTitle"]))
    story.append(Paragraph(
        f"Generated {datetime.now().strftime('%d %b %Y, %H:%M')} &nbsp;|&nbsp; "
        f"Patient: {patient_info.get('name', 'N/A')}", styles["MSMSubtitle"]))

    story.append(Paragraph("Patient Details", styles["MSMHeading"]))
    story.append(_table([
        ["Name", patient_info.get("name", "-")],
        ["Date of Birth", patient_info.get("dob", "-")],
        ["Gender", patient_info.get("gender", "-")],
        ["Contact Number", patient_info.get("contact_number", "-")],
        ["Family Email", patient_info.get("family_email", "-")],
    ], col_widths=[45 * mm, 110 * mm]))

    story.append(Paragraph("Previous Visit Summary", styles["MSMHeading"]))
    story.append(_table([
        ["Attending Doctor", "Visit Date", "Notes"],
        [last_visit.get("doctor_name", "-"), last_visit.get("visit_date", "-"),
         last_visit.get("notes", "-")],
    ], col_widths=[45 * mm, 35 * mm, 75 * mm]))

    story.append(Paragraph("Currently Prescribed Medicines", styles["MSMHeading"]))
    med_rows = [["Medicine", "Dosage", "Frequency", "Time", "Start – End"]]
    for m in medicines:
        med_rows.append([m["name"], m.get("dosage", "-"), m.get("frequency", "-"),
                          m.get("time_of_day", "-"),
                          f"{m.get('start_date', '-')} – {m.get('end_date', '-')}"])
    story.append(_table(med_rows, col_widths=[35 * mm, 25 * mm, 30 * mm, 25 * mm, 40 * mm]))

    story.append(Paragraph("Doses Taken vs. Missed (this period)", styles["MSMHeading"]))
    comp_rows = [["Medicine", "Expected", "Taken", "Missed", "Unconfirmed", "Adherence %"]]
    for c in compliance_summary:
        comp_rows.append([c["medicine"], str(c["scheduled"]), str(c["taken"]),
                           str(c["missed"]), str(c.get("unconfirmed", 0)), f"{c['adherence']:.1f}%"])
    story.append(_table(comp_rows, col_widths=[32 * mm, 20 * mm, 18 * mm, 18 * mm, 27 * mm, 25 * mm]))

    story.append(Paragraph("Refill Status", styles["MSMHeading"]))
    refill_rows = [["Medicine", "Remaining Qty", "Threshold", "Alert?", "Last Refill"]]
    for r in refills:
        alert = "YES — Refill Needed" if r["alert"] else "OK"
        refill_rows.append([r["medicine"], str(r["remaining_qty"]), str(r["threshold"]),
                             alert, r.get("last_refill_date", "-")])
    story.append(_table(refill_rows, col_widths=[35 * mm, 28 * mm, 24 * mm, 40 * mm, 28 * mm]))

    story.append(Paragraph("Next Doctor's Visit", styles["MSMHeading"]))
    story.append(_table([
        ["Doctor", "Scheduled Date"],
        [next_visit.get("doctor_name", "Not scheduled"), next_visit.get("visit_date", "-")],
    ], col_widths=[45 * mm, 110 * mm]))

    story.append(Spacer(1, 14 * mm))
    story.append(Paragraph(
        "This report was generated entirely on-device. Sensitive fields were "
        "decrypted in memory only for the duration of this PDF's creation and "
        "are not stored in plaintext elsewhere.", styles["MSMSubtitle"]))

    doc.build(story)
    return buf.getvalue()


def generate_visit_summary_report(patient_info: dict, medicines_since_last_visit: list,
                                   last_visit: dict) -> bytes:
    """
    Inter-Visit Patient Summary Report (Section IV-E): a clinically
    oriented document covering the record from the last visit until
    now, generated on-demand for the Doctor.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                             topMargin=20 * mm, bottomMargin=18 * mm,
                             leftMargin=18 * mm, rightMargin=18 * mm)
    styles = _styles()
    story = []

    story.append(Paragraph("MySmartMed — Inter-Visit Patient Summary", styles["MSMTitle"]))
    story.append(Paragraph(
        f"Generated {datetime.now().strftime('%d %b %Y, %H:%M')} &nbsp;|&nbsp; "
        f"Patient: {patient_info.get('name', 'N/A')} &nbsp;|&nbsp; "
        f"Since last visit: {last_visit.get('visit_date', '-')}", styles["MSMSubtitle"]))

    story.append(Paragraph("Patient", styles["MSMHeading"]))
    story.append(_table([
        ["Name", patient_info.get("name", "-")],
        ["Date of Birth", patient_info.get("dob", "-")],
        ["Gender", patient_info.get("gender", "-")],
    ], col_widths=[45 * mm, 110 * mm]))

    story.append(Paragraph("Last Visit", styles["MSMHeading"]))
    story.append(_table([
        ["Attending Doctor", "Visit Date", "Notes"],
        [last_visit.get("doctor_name", "-"), last_visit.get("visit_date", "-"),
         last_visit.get("notes", "-")],
    ], col_widths=[45 * mm, 35 * mm, 75 * mm]))

    story.append(Paragraph("Medicines & Adherence Since Last Visit", styles["MSMHeading"]))
    rows = [["Medicine", "Dosage", "Adherence %", "Doses Missed"]]
    for m in medicines_since_last_visit:
        rows.append([m["name"], m.get("dosage", "-"),
                      f"{m.get('adherence', 0):.1f}%", str(m.get("missed", 0))])
    story.append(_table(rows, col_widths=[45 * mm, 30 * mm, 35 * mm, 35 * mm]))

    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph(
        "For clinician reference during the upcoming consultation. "
        "Generated locally on the caregiver's device.", styles["MSMSubtitle"]))

    doc.build(story)
    return buf.getvalue()
