# annexes.py — توليد ملاحق المرسوم 2.23.700
import io
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import arabic_reshaper
from bidi.algorithm import get_display

def ar(text):
    return get_display(arabic_reshaper.reshape(str(text)))

def get_style():
    try:
        pdfmetrics.registerFont(TTFont('Arabic', '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'))
        fname = 'Arabic'
    except:
        fname = 'Helvetica'
    title_style = ParagraphStyle('title', fontName=fname, fontSize=13, alignment=TA_CENTER, spaceAfter=10)
    header_style = ParagraphStyle('header', fontName=fname, fontSize=9, alignment=TA_RIGHT)
    return fname, title_style, header_style

def get_building_category(residence_id, year, db):
    from sqlalchemy import text
    with db.engine.connect() as conn:
        total = conn.execute(text(
            "SELECT COALESCE(SUM(amount),0) FROM payments WHERE year=:y AND apartment_id IN "
            "(SELECT id FROM apartments WHERE residence_id=:r)"
        ), {'y': year, 'r': residence_id}).scalar()
    if total <= 200000:
        return 'صغيرة', ['10', '13-1', '13-2'], total
    elif total <= 500000:
        return 'متوسطة', ['10', '11', '12'], total
    else:
        return 'كبيرة', ['3','4','5','6','7','8','9','10'], total

def generate_annexe_10(residence_id, year, db):
    from sqlalchemy import text
    with db.engine.connect() as conn:
        apts = conn.execute(text(
            "SELECT id, number, owner_name, monthly_fee FROM apartments WHERE residence_id=:r"
        ), {'r': residence_id}).fetchall()
        rows = []
        total_called = total_paid = total_balance = 0
        for apt in apts:
            called = conn.execute(text(
                "SELECT COALESCE(SUM(amount),0) FROM payments WHERE apartment_id=:a AND year=:y"
            ), {'a': apt[0], 'y': year}).scalar()
            paid = conn.execute(text(
                "SELECT COALESCE(SUM(amount),0) FROM payments WHERE apartment_id=:a AND year=:y AND status='paid'"
            ), {'a': apt[0], 'y': year}).scalar()
            balance = called - paid
            total_called += called; total_paid += paid; total_balance += balance
            rows.append([ar(apt[1]), ar(apt[2] or '-'), f"{called:.2f}", f"{paid:.2f}", f"{balance:.2f}"])
        rows.append([ar('المجموع'), '', f"{total_called:.2f}", f"{total_paid:.2f}", f"{total_balance:.2f}"])
    return rows

def generate_annexe_13_1(residence_id, year, db):
    from sqlalchemy import text
    with db.engine.connect() as conn:
        total_payments = conn.execute(text(
            "SELECT COALESCE(SUM(amount),0) FROM payments WHERE year=:y AND apartment_id IN "
            "(SELECT id FROM apartments WHERE residence_id=:r)"
        ), {'y': year, 'r': residence_id}).scalar()
        total_expenses = conn.execute(text(
            "SELECT COALESCE(SUM(amount),0) FROM expenses WHERE residence_id=:r AND strftime('%Y',date)=:y"
        ), {'r': residence_id, 'y': str(year)}).scalar()
        reserve = conn.execute(text(
            "SELECT COALESCE(balance,0) FROM reserve_fund WHERE residence_id=:r"
        ), {'r': residence_id}).scalar() or 0
    net = total_payments - total_expenses
    rows = [
        [ar('المداخيل — المبالغ المحصلة'), f"{total_payments:.2f}"],
        [ar('المصاريف الإجمالية'), f"{total_expenses:.2f}"],
        [ar('صندوق الاحتياط'), f"{reserve:.2f}"],
        [ar('الرصيد الصافي'), f"{net:.2f}"],
    ]
    return rows

def build_pdf(residence_id, year, annexe_num, db):
    fname, title_style, header_style = get_style()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    elements = []

    elements.append(Paragraph(ar(f"المملكة المغربية — المرسوم 2.23.700"), header_style))
    elements.append(Paragraph(ar(f"الملحق رقم {annexe_num} — السنة المالية {year}"), title_style))
    elements.append(Spacer(1, 10))

    if annexe_num == '10':
        headers = [ar('الشقة'), ar('المالك'), ar('المستدعى'), ar('المدفوع'), ar('الرصيد')]
        data = [headers] + generate_annexe_10(residence_id, year, db)
        col_widths = [60, 130, 80, 80, 80]
    elif annexe_num == '13-1':
        headers = [ar('البيان'), ar('المبلغ (درهم)')]
        data = [headers] + generate_annexe_13_1(residence_id, year, db)
        col_widths = [280, 150]
    elif annexe_num == '13-2':
        headers = [ar('البيان'), ar('المبلغ (درهم)')]
        data = [headers, [ar('رصيد صندوق الاحتياط'), '—'], [ar('ديون الموردين'), '—']]
        col_widths = [280, 150]
    else:
        data = [[ar('الملحق'), ar(annexe_num)], [ar('قيد التطوير'), '—']]
        col_widths = [280, 150]

    table = Table(data, colWidths=col_widths)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a3c5e')),
        ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
        ('FONTNAME',   (0,0), (-1,-1), fname),
        ('FONTSIZE',   (0,0), (-1,-1), 9),
        ('ALIGN',      (0,0), (-1,-1), 'RIGHT'),
        ('GRID',       (0,0), (-1,-1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f0f4f8')]),
        ('BACKGROUND', (0,-1), (-1,-1), colors.HexColor('#e8f0fe')),
    ]))
    elements.append(table)
    doc.build(elements)
    buf.seek(0)
    return buf

