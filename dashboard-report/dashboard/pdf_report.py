"""PDF export for the selected security event range."""
import html
from datetime import datetime
from io import BytesIO
from pathlib import Path
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from .config import APP_TZ

def make_pdf_report(events: pd.DataFrame, start: datetime, end: datetime) -> bytes:
    font_candidates = [
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("C:/Windows/Fonts/arial.ttf"),
    ]
    font_path = next((path for path in font_candidates if path.is_file()), None)
    font_name = "Helvetica"
    if font_path:
        pdfmetrics.registerFont(TTFont("SOCUnicode", str(font_path)))
        font_name = "SOCUnicode"
    buffer = BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=landscape(A4), leftMargin=12*mm, rightMargin=12*mm,
                                 topMargin=13*mm, bottomMargin=14*mm, title="SOC Security Report")
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontName=font_name,
                                 textColor=colors.HexColor("#0a246a"), fontSize=18)
    body_style = ParagraphStyle("ReportBody", parent=styles["BodyText"], fontName=font_name)
    heading_style = ParagraphStyle("ReportHeading", parent=styles["Heading3"], fontName=font_name)
    italic_style = ParagraphStyle("ReportItalic", parent=styles["Italic"], fontName=font_name)
    cell_style = ParagraphStyle("ReportCell", parent=styles["BodyText"], fontName=font_name, fontSize=7, leading=9)
    story = [
        Paragraph("Báo cáo đánh giá an ninh SOC", title_style),
        Paragraph("BÁO CÁO SỰ KIỆN BẢO MẬT VÀ ĐỀ XUẤT PHÂN TÍCH AI", heading_style),
        Spacer(1, 5*mm),
        Paragraph(f"Khoảng thời gian: {start.strftime('%d/%m/%Y %H:%M')} – {end.strftime('%d/%m/%Y %H:%M')} (UTC+07)", body_style),
        Paragraph(f"Thời điểm tạo: {datetime.now(APP_TZ).strftime('%d/%m/%Y %H:%M:%S')} (UTC+07)", body_style),
        Spacer(1, 3*mm),
    ]
    total = len(events)
    critical = int((events["risk_score"].str.lower() == "critical").sum()) if total else 0
    high = int((events["risk_score"].str.lower() == "high").sum()) if total else 0
    story.append(Paragraph(f"Tổng sự kiện: {total} · Nghiêm trọng: {critical} · Mức cao: {high}", heading_style))
    headers = ["Thời điểm", "IP nguồn", "Phân loại", "Mức độ", "Giải thích", "Tương quan", "Đề xuất xử lý", "Log gốc"]
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
        ("FONTNAME", (0, 0), (-1, 0), font_name),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f5f3e9")),
        ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#7f9db9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)
    if total > 300:
        story.insert(8, Paragraph("Hiển thị 300 sự kiện mới nhất trong tối đa 10.000 sự kiện đã tải.", italic_style))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#0a246a"))
        canvas.setFont(font_name, 8)
        canvas.drawString(12*mm, 7*mm, "Báo cáo đánh giá an ninh SOC")
        canvas.drawRightString(landscape(A4)[0] - 12*mm, 7*mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
