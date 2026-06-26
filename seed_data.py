"""
seed_data.py — بيانات تجريبية واقعية لـ SyndikPro
شغّله مرة واحدة: python seed_data.py
"""
from app import app, db
from models import User, Residence, Apartment, Payment, Complaint, Expense
from werkzeug.security import generate_password_hash
from datetime import date, datetime

with app.app_context():

    # ── مسح القديم ──────────────────────────────
    db.drop_all()
    db.create_all()

    # ══════════════════════════════════════════════
    #  UTILISATEUR — السانديك
    # ══════════════════════════════════════════════
    hicham = User(
        username      = 'hicham',
        password_hash = generate_password_hash('1234'),
        full_name     = 'هشام المدير',
        role          = 'syndic',
    )
    db.session.add(hicham)
    db.session.flush()

    # ══════════════════════════════════════════════
    #  RÉSIDENCE — إقامة الياسمين
    # ══════════════════════════════════════════════
    res = Residence(
        user_id      = hicham.id,
        name         = 'إقامة الياسمين',
        address      = 'شارع محمد الخامس رقم 12',
        city         = 'الدار البيضاء',
        total_floors = 4,
    )
    db.session.add(res)
    db.session.flush()

    # ══════════════════════════════════════════════
    #  APPARTEMENTS — 12 شقة في 4 طوابق
    # ══════════════════════════════════════════════
    apts_data = [
        # (رقم, طابق, المالك,              الهاتف,        الساكن,             هاتف ساكن,     واجب)
        ('01', 0, 'محمد العلوي',          '0661-234-567', '',                 '',            300),
        ('02', 0, 'فاطمة الزهراء بنعلي', '0662-345-678', '',                 '',            300),
        ('03', 0, 'عبد الرحيم الشرقي',   '0663-456-789', 'يوسف الشرقي',     '0663-456-000', 300),
        ('11', 1, 'سمير الحسني',          '0664-567-890', '',                 '',            250),
        ('12', 1, 'نادية أوشن',           '0665-678-901', '',                 '',            250),
        ('13', 1, 'رضا بنمسعود',          '0666-789-012', 'آمنة بنمسعود',    '0666-789-100', 250),
        ('21', 2, 'حميد التازي',           '0667-890-123', '',                 '',            250),
        ('22', 2, 'خديجة بوهلال',         '0668-901-234', '',                 '',            250),
        ('23', 2, 'عمر الفاسي',           '0669-012-345', 'سارة الفاسي',     '0669-012-000', 250),
        ('31', 3, 'ليلى المنصوري',        '0670-123-456', '',                 '',            200),
        ('32', 3, 'كريم بوعزة',           '0671-234-567', '',                 '',            200),
        ('33', 3, 'إيمان الدريوش',        '0672-345-678', 'حسن الدريوش',     '0672-345-000', 200),
    ]

    apts = []
    for num, floor, owner, oph, tenant, tph, fee in apts_data:
        a = Apartment(
            residence_id = res.id,
            number       = num,
            floor        = floor,
            owner_name   = owner,
            owner_phone  = oph,
            tenant_name  = tenant,
            tenant_phone = tph,
            monthly_fee  = fee,
            apt_type     = 'سكني',
        )
        db.session.add(a)
        apts.append(a)
    db.session.flush()

    # ══════════════════════════════════════════════
    #  PAYMENTS — 4 أشهر من الأداءات
    #  فبراير / مارس / أبريل / مايو 2026
    # ══════════════════════════════════════════════

    # فبراير — الجميع دفعوا
    for a in apts:
        db.session.add(Payment(
            apartment_id = a.id,
            month=2, year=2026,
            amount    = a.monthly_fee,
            date_paid = date(2026, 2, 5),
            status    = 'paid',
        ))

    # مارس — واحد لم يدفع (حميد التازي ش21)
    for a in apts:
        if a.number == '21':
            continue  # لم يدفع
        db.session.add(Payment(
            apartment_id = a.id,
            month=3, year=2026,
            amount    = a.monthly_fee,
            date_paid = date(2026, 3, 8),
            status    = 'paid',
        ))

    # أبريل — اثنان لم يدفعوا (حميد ش21، كريم ش32)
    for a in apts:
        if a.number in ('21', '32'):
            continue
        status = 'partial' if a.number == '13' else 'paid'
        amount = 150 if a.number == '13' else a.monthly_fee
        db.session.add(Payment(
            apartment_id = a.id,
            month=4, year=2026,
            amount    = amount,
            date_paid = date(2026, 4, 10),
            status    = status,
            note      = 'دفع جزئي - الباقي في الأسبوع القادم' if a.number == '13' else '',
        ))

    # مايو — 4 لم يدفعوا بعد
    unpaid_may = ('21', '32', '02', '33')
    for a in apts:
        if a.number in unpaid_may:
            continue
        db.session.add(Payment(
            apartment_id = a.id,
            month=5, year=2026,
            amount    = a.monthly_fee,
            date_paid = date(2026, 5, 3),
            status    = 'paid',
        ))

    # ══════════════════════════════════════════════
    #  COMPLAINTS — شكايات واقعية
    # ══════════════════════════════════════════════
    def apt(num): return next(a for a in apts if a.number == num)

    complaints_data = [
        (apt('11'), 'عطل المصعد',
         'المصعد متوقف منذ 3 أيام، يسبب صعوبة كبيرة لكبار السن في الطابق الثالث.',
         'high', 'open', date(2026, 5, 26), None),

        (apt('21'), 'تسرب مياه في السقف',
         'يوجد تسرب مياه في سقف الصالون عند المطر، والوضع يزداد سوءاً.',
         'high', 'progress', date(2026, 5, 20), None),

        (apt('01'), 'إنارة السلم معطوبة',
         'المصابيح في الطابق الأول والثاني معطوبة منذ أسبوع.',
         'medium', 'open', date(2026, 5, 27), None),

        (apt('33'), 'ضوضاء ليلية مزعجة',
         'بعض السكان يسببون ضوضاء بعد منتصف الليل مما يزعج الجيران.',
         'medium', 'progress', date(2026, 5, 15), None),

        (apt('12'), 'مشكلة في باب المدخل',
         'باب المدخل الرئيسي لا يُغلق بشكل صحيح، خطر أمني.',
         'high', 'closed', date(2026, 5, 1), date(2026, 5, 10)),

        (apt('03'), 'نظافة المدخل',
         'تراكم النفايات أمام المدخل، يجب التنبيه على عامل النظافة.',
         'low', 'closed', date(2026, 4, 20), date(2026, 4, 25)),
    ]

    for apt_obj, title, desc, priority, status, d_created, d_closed in complaints_data:
        c = Complaint(
            apartment_id = apt_obj.id,
            title        = title,
            description  = desc,
            priority     = priority,
            status       = status,
            date_created = datetime.combine(d_created, datetime.min.time()),
            date_closed  = datetime.combine(d_closed, datetime.min.time()) if d_closed else None,
        )
        db.session.add(c)

    # ══════════════════════════════════════════════
    #  EXPENSES — مصاريف مشتركة
    # ══════════════════════════════════════════════
    expenses_data = [
        ('عامل النظافة — أبريل',    400,  'نظافة',  date(2026, 4, 30)),
        ('فاتورة الكهرباء — أبريل', 320,  'كهرباء', date(2026, 4, 28)),
        ('صيانة المصعد',             850,  'صيانة',  date(2026, 5, 10)),
        ('عامل النظافة — مايو',      400,  'نظافة',  date(2026, 5, 30)),
        ('فاتورة الكهرباء — مايو',  305,  'كهرباء', date(2026, 5, 28)),
        ('شراء لمبات الإنارة',       180,  'صيانة',  date(2026, 5, 27)),
        ('طلاء المدخل',              1200, 'صيانة',  date(2026, 3, 15)),
    ]

    for title, amount, cat, d in expenses_data:
        db.session.add(Expense(
            residence_id = res.id,
            title        = title,
            amount       = amount,
            category     = cat,
            date         = d,
        ))

    db.session.commit()

    # ══════════════════════════════════════════════
    #  ملخص
    # ══════════════════════════════════════════════
    print("✅ تمت إضافة البيانات التجريبية بنجاح!")
    print()
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"🏢 الإقامة : {res.name}")
    print(f"🏠 الشقق   : {len(apts)} شقة في 4 طوابق")
    print(f"💰 المدفوعات: 4 أشهر من السجل")
    print(f"📋 الشكايات: {len(complaints_data)} شكاية")
    print(f"💸 المصاريف: {len(expenses_data)} عملية")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()
    print("👤 تسجيل الدخول:")
    print("   المستخدم  : hicham")
    print("   كلمة المرور: 1234")
