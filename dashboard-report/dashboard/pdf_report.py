"""PDF export for the selected security event range."""
import html
from datetime import datetime
from io import BytesIO
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from .config import APP_TZ

def make_pdf_report(events: pd.DataFrame, start: datetime, end: datetime) -> bytes:
    buffer = BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=landscape(A4), leftMargin=12*mm, rightMargin=12*mm,
                                 topMargin=13*mm, bottomMargin=14*mm, title="SOC Security Report")
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], textColor=colors.HexColor("#0a246a"), fontSize=18)
    cell_style = ParagraphStyle("ReportCell", parent=styles["BodyText"], fontSize=7, leading=9)
    story = [
        Paragraph("SOC Security Assessment Report", title_style),
        Paragraph("TÌM HIỂU VÀ XÂY DỰNG HỆ THỐNG WEB APPLICATION FIREWALL OPEN SOURCE TÍCH HỢP AI PHÂN TÍCH TẤN CÔNG", styles["Heading3"]),
        Paragraph("AI-Enhanced Open Source WAF Security Assessment Lab", styles["Italic"]),
        Paragraph("Đặng Thanh Lâm (ID: 25410078) · Trương Tấn Đạt (ID: 25410031)", styles["Normal"]),
        Spacer(1, 5*mm),
        Paragraph(f"Range: {start.strftime('%Y-%m-%d %H:%M')} – {end.strftime('%Y-%m-%d %H:%M')} (Asia/Ho_Chi_Minh)", styles["Normal"]),
        Paragraph(f"Generated: {datetime.now(APP_TZ).strftime('%Y-%m-%d %H:%M:%S')} (UTC+07:00)", styles["Normal"]),
        Spacer(1, 3*mm),
    ]
    total = len(events)
    critical = int((events["risk_score"].str.lower() == "critical").sum()) if total else 0
    high = int((events["risk_score"].str.lower() == "high").sum()) if total else 0
    story.append(Paragraph(f"Events: {total} · Critical: {critical} · High: {high}", styles["Heading3"]))
    headers = ["Timestamp", "Client IP", "Classification", "Risk", "Explanation", "Correlation", "Recommendation", "Raw log"]
    rows = [headers]
    for _, item in events.head(300).iterrows():
        timestamp = pd.to_datetime(item["timestamp"], utc=True, errors="coerce")
        stamp = timestamp.tz_convert(APP_TZ).strftime("%Y-%m-%d %H:%M:%S") if not pd.isna(timestamp) else ""
        values = [stamp, item.get("client_ip") or "", item.get("classification") or "", item.get("risk_score") or "",
                  str(item.get("explanation") or "")[:500], str(item.get("correlation") or "")[:350],
                  str(item.get("recommendation") or "")[:500], str(item.get("raw_log") or "")[:250]]
        rows.append([Paragraph(html.escape(str(value)).replace("\n", "<br/>"), cell_style) for value in values])
    table = Table(rows, colWidths=[24*mm, 19*mm, 24*mm, 13*mm, 48*mm, 36*mm, 40*mm, 30*mm], repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a246a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f5f3e9")),
        ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#7f9db9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)
    if total > 300:
        story.insert(8, Paragraph("Showing the newest 300 of 10,000 loaded events.", styles["Italic"]))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#0a246a"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(12*mm, 7*mm, "SOC Security Assessment Report")
        canvas.drawRightString(landscape(A4)[0] - 12*mm, 7*mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
