from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# ══════════════════════════════════════════
#  USER — Admin / Syndic
# ══════════════════════════════════════════
class User(db.Model):
    __tablename__ = 'users'
    id                 = db.Column(db.Integer, primary_key=True)
    username           = db.Column(db.String(80),  unique=True, nullable=False)
    password_hash      = db.Column(db.String(200), nullable=False)
    full_name          = db.Column(db.String(120))
    phone              = db.Column(db.String(20))
    email              = db.Column(db.String(120))
    city               = db.Column(db.String(80))
    neighborhood       = db.Column(db.String(80))
    country            = db.Column(db.String(80), default='المغرب')
    role               = db.Column(db.String(20), default='syndic')  # admin | syndic
    status             = db.Column(db.String(20), default='pending') # pending|active|rejected|expired
    plan               = db.Column(db.String(20), default='free')    # free|basic|pro|enterprise
    payment_proof      = db.Column(db.String(300))
    pay_method         = db.Column(db.String(30))
    payment_method      = db.Column(db.String(30))
    total_amount        = db.Column(db.Float, default=0)
    duration_months     = db.Column(db.Integer, default=1)
    paypal_email       = db.Column(db.String(120))   # PayPal account for receiving payments
    bank_rib           = db.Column(db.String(30))    # RIB pour virement/CMI
    bank_name          = db.Column(db.String(100))   # Nom de la banque
    payment_date       = db.Column(db.DateTime)
    subscription_start = db.Column(db.DateTime)
    subscription_end   = db.Column(db.DateTime)
    approved_by        = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    approved_at        = db.Column(db.DateTime)
    subscription_confirmed = db.Column(db.Boolean, default=False)
    created_at         = db.Column(db.DateTime, default=datetime.utcnow)
    email_verified    = db.Column(db.Boolean, default=False)
    email_verified_at  = db.Column(db.DateTime)
    otp_code           = db.Column(db.String(6))
    otp_expires_at     = db.Column(db.DateTime)

    residences = db.relationship('Residence', backref='syndic', lazy=True, foreign_keys='Residence.user_id')

    def to_dict(self):
        days_left = 0
        if self.subscription_end:
            delta = self.subscription_end - datetime.utcnow()
            days_left = max(0, delta.days)
        return {
            'id':               self.id,
            'username':         self.username,
            'full_name':        self.full_name or '',
            'phone':            self.phone or '',
            'email':            self.email or '',
            'city':             self.city or '',
            'neighborhood':     self.neighborhood or '',
            'country':          self.country or 'المغرب',
            'role':             self.role,
            'status':           self.status,
            'plan':             self.plan or 'free',
            'subscription_confirmed': bool(self.subscription_confirmed),
            'payment_proof':    self.payment_proof or '',
        'pay_method':       self.pay_method if hasattr(self,'pay_method') else '',
            'paypal_email':     self.paypal_email or '',
            'bank_rib':         self.bank_rib or '',
            'bank_name':        self.bank_name or '',
            'subscription_start': self.subscription_start.strftime('%d/%m/%Y') if self.subscription_start else '',
            'subscription_end': self.subscription_end.strftime('%d/%m/%Y') if self.subscription_end else '',
            'days_left':        days_left,
            'approved_at':      self.approved_at.strftime('%d/%m/%Y') if self.approved_at else '',
            'created_at':       self.created_at.strftime('%d/%m/%Y %H:%M'),
            'residences_count': len(self.residences),
        'payment_method':   self.payment_method or '',
        'total_amount':     self.total_amount or 0,
        'duration_months':  self.duration_months or 1,
        }


# ══════════════════════════════════════════
#  SUBSCRIPTION PLAN
# ══════════════════════════════════════════
class SubscriptionPlan(db.Model):
    __tablename__ = 'subscription_plans'
    id             = db.Column(db.Integer, primary_key=True)
    name           = db.Column(db.String(50), nullable=False)   # free|basic|pro|enterprise
    label          = db.Column(db.String(80))
    price_monthly  = db.Column(db.Float, default=0)
    max_residences = db.Column(db.Integer, default=1)
    max_apartments = db.Column(db.Integer, default=20)
    max_buildings  = db.Column(db.Integer, default=6)
    features       = db.Column(db.Text)   # JSON list
    is_active      = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            'id':             self.id,
            'name':           self.name,
            'label':          self.label or self.name,
            'price_monthly':  self.price_monthly,
            'max_residences': self.max_residences,
            'max_buildings':  self.max_buildings,
            'max_apartments': self.max_apartments,
            'features':       self.features or '',
            'is_active':      self.is_active,
        }



# ══════════════════════════════════════════
#  BUILDING — عمارة
# ══════════════════════════════════════════

# ══════════════════════════════════════════
#  SUBSCRIPTION DISCOUNT - خصم الاشتراك
# ══════════════════════════════════════════
class SubscriptionDiscount(db.Model):
    __tablename__ = 'subscription_discounts'
    id             = db.Column(db.Integer, primary_key=True)
    min_months     = db.Column(db.Integer)        # الحد الأدنى للشهور
    max_months     = db.Column(db.Integer)        # الحد الأقصى للشهور
    discount_percent = db.Column(db.Float)       # نسبة الخصم
    
    def to_dict(self):
        return {
            'id': self.id,
            'min_months': self.min_months,
            'max_months': self.max_months,
            'discount_percent': self.discount_percent,
        }

class Building(db.Model):
    __tablename__ = 'buildings'
    id           = db.Column(db.Integer, primary_key=True)
    residence_id = db.Column(db.Integer, db.ForeignKey('residences.id'), nullable=False)
    name         = db.Column(db.String(50), nullable=False)
    total_floors = db.Column(db.Integer, default=1)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    viewed_by    = db.Column(db.Text, default='[]')
    viewed_count = db.Column(db.Integer, default=0)

    apartments = db.relationship('Apartment', backref='building', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'residence_id': self.residence_id,
            'name': self.name,
            'total_floors': self.total_floors,
            'apartments_count': len(self.apartments),
        }

# ══════════════════════════════════════════
#  RESIDENCE
# ══════════════════════════════════════════
class Residence(db.Model):
    __tablename__ = 'residences'
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name         = db.Column(db.String(120), nullable=False)
    address      = db.Column(db.String(200))
    city         = db.Column(db.String(80))
    neighborhood = db.Column(db.String(80))
    total_floors = db.Column(db.Integer, default=0)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    apartments = db.relationship('Apartment', backref='residence', lazy=True, cascade='all, delete-orphan')
    expenses   = db.relationship('Expense',   backref='residence', lazy=True, cascade='all, delete-orphan')


# ══════════════════════════════════════════
#  APARTMENT
# ══════════════════════════════════════════
class Apartment(db.Model):
    __tablename__ = 'apartments'
    id           = db.Column(db.Integer, primary_key=True)
    residence_id = db.Column(db.Integer, db.ForeignKey('residences.id'), nullable=False)
    number       = db.Column(db.String(10), nullable=False)
    floor        = db.Column(db.Integer, default=0)
    owner_name   = db.Column(db.String(120))
    owner_phone  = db.Column(db.String(20))
    tenant_name  = db.Column(db.String(120))
    tenant_phone = db.Column(db.String(20))
    monthly_fee  = db.Column(db.Float, default=250.0)
    apt_type     = db.Column(db.String(20), default='سكني')
    notes        = db.Column(db.Text)
    building_id  = db.Column(db.Integer, db.ForeignKey('buildings.id'), nullable=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    payments   = db.relationship('Payment',   backref='apartment', lazy=True, cascade='all, delete-orphan')
    complaints = db.relationship('Complaint', backref='apartment', lazy=True, cascade='all, delete-orphan')

    def to_dict(self, month=None, year=None):
        now = datetime.utcnow()
        m = month or now.month
        y = year  or now.year
        pay = Payment.query.filter_by(apartment_id=self.id, month=m, year=y).first()
        status = pay.status if pay else 'unpaid'
        unpaid = Payment.query.filter_by(apartment_id=self.id, status='unpaid').count()
        return {
            'id': self.id, 'residence_id': self.residence_id,
            'number': self.number, 'floor': self.floor,
            'owner_name': self.owner_name or '', 'owner_phone': self.owner_phone or '',
            'tenant_name': self.tenant_name or '', 'tenant_phone': self.tenant_phone or '',
            'monthly_fee': self.monthly_fee, 'apt_type': self.apt_type,
            'notes': self.notes or '', 'pay_status': status, 'unpaid_months': unpaid, 'building_id': self.building_id,
        }


# ══════════════════════════════════════════
#  PAYMENT
# ══════════════════════════════════════════
class Payment(db.Model):
    __tablename__ = 'payments'
    id           = db.Column(db.Integer, primary_key=True)
    apartment_id = db.Column(db.Integer, db.ForeignKey('apartments.id'), nullable=False)
    month        = db.Column(db.Integer, nullable=False)
    year         = db.Column(db.Integer, nullable=False)
    amount       = db.Column(db.Float, nullable=False)
    date_paid    = db.Column(db.Date)
    status       = db.Column(db.String(20), default='unpaid')  # paid|unpaid|partial
    method       = db.Column(db.String(30), default='نقدي')    # نقدي|تحويل|بطاقة
    note         = db.Column(db.String(200))
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        apt = Apartment.query.get(self.apartment_id)
        return {
            'id': self.id, 'apartment_id': self.apartment_id,
            'apt_number': apt.number if apt else '?',
            'owner_name': apt.owner_name if apt else '?',
            'month': self.month, 'year': self.year,
            'amount': self.amount,
            'date_paid': self.date_paid.isoformat() if self.date_paid else None,
            'status': self.status, 'method': self.method or 'نقدي',
            'note': self.note or '',
        }


# ══════════════════════════════════════════
#  COMPLAINT
# ══════════════════════════════════════════
class Complaint(db.Model):
    __tablename__ = 'complaints'
    id           = db.Column(db.Integer, primary_key=True)
    apartment_id = db.Column(db.Integer, db.ForeignKey('apartments.id'), nullable=False)
    title        = db.Column(db.String(120), nullable=False)
    description  = db.Column(db.Text)
    priority     = db.Column(db.String(20), default='medium')  # high|medium|low
    status       = db.Column(db.String(20), default='open')    # open|progress|closed
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    date_closed  = db.Column(db.DateTime)
    photo_path   = db.Column(db.String(300))
    photo_path   = db.Column(db.String(300))
    admin_note   = db.Column(db.Text, nullable=False)

    def to_dict(self):
        apt = Apartment.query.get(self.apartment_id)
        return {
            'id': self.id, 'apartment_id': self.apartment_id,
            'apt_number': apt.number if apt else '?',
            'owner_name': apt.owner_name if apt else '?',
            'title': self.title, 'description': self.description or '',
            'priority': self.priority, 'status': self.status,
            'date_created': self.date_created.strftime('%d/%m/%Y'),
            'date_closed': self.date_closed.strftime('%d/%m/%Y') if self.date_closed else None,
            'photo_path': self.photo_path or '',
            'photo_path': self.photo_path or '',
            'photo_path': self.photo_path or '',
            'admin_note': self.admin_note or '',
            'photo_path': self.photo_path if hasattr(self, 'photo_path') else '',
        }


# ══════════════════════════════════════════
#  EXPENSE
# ══════════════════════════════════════════
class Expense(db.Model):
    __tablename__ = 'expenses'
    id           = db.Column(db.Integer, primary_key=True)
    residence_id = db.Column(db.Integer, db.ForeignKey('residences.id'), nullable=False)
    title        = db.Column(db.String(120), nullable=False)
    amount       = db.Column(db.Float, nullable=False)
    category     = db.Column(db.String(50), default='أخرى')
    date         = db.Column(db.Date, nullable=False)
    note         = db.Column(db.String(200))
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'residence_id': self.residence_id,
            'title': self.title, 'amount': self.amount,
            'category': self.category, 'date': self.date.isoformat(),
            'note': self.note or '',
        }


# ══════════════════════════════════════════
#  WORKER
# ══════════════════════════════════════════
class Worker(db.Model):
    __tablename__ = 'workers'
    id           = db.Column(db.Integer, primary_key=True)
    residence_id = db.Column(db.Integer, db.ForeignKey('residences.id'), nullable=False)
    full_name    = db.Column(db.String(120), nullable=False)
    role         = db.Column(db.String(50), default='حارس')
    phone        = db.Column(db.String(20))
    cin          = db.Column(db.String(20))
    cnss_number  = db.Column(db.String(30))
    cnss_status  = db.Column(db.String(20), default='غير مسجل')
    salary       = db.Column(db.Float, default=0)
    start_date   = db.Column(db.Date)
    status       = db.Column(db.String(20), default='active')
    notes        = db.Column(db.Text)
    photo        = db.Column(db.String(255))

    def to_dict(self):
        return {
            'id': self.id, 'residence_id': self.residence_id,
            'full_name': self.full_name, 'role': self.role,
            'phone': self.phone or '', 'cin': self.cin or '',
            'cnss_number': self.cnss_number or '', 'cnss_status': self.cnss_status,
            'salary': self.salary,
            'start_date': self.start_date.isoformat() if self.start_date else None,
            'status': self.status, 'notes': self.notes or '',
            'photo': self.photo or '',
        }


# ══════════════════════════════════════════
#  RESIDENT — ساكن
# ══════════════════════════════════════════
class Resident(db.Model):
    __tablename__ = 'residents'
    id            = db.Column(db.Integer, primary_key=True)
    first_name    = db.Column(db.String(80), nullable=False)
    last_name     = db.Column(db.String(80), nullable=False)
    cin           = db.Column(db.String(20), unique=True, nullable=False)
    phone         = db.Column(db.String(20))
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    country       = db.Column(db.String(80), default='المغرب')
    floor         = db.Column(db.Integer)
    apt_number    = db.Column(db.String(20))
    residence_id  = db.Column(db.Integer, db.ForeignKey('residences.id'), nullable=False)
    apartment_id  = db.Column(db.Integer, db.ForeignKey('apartments.id'), nullable=False)
    resident_type = db.Column(db.String(20), default='owner')  # owner | tenant
    status        = db.Column(db.String(20), default='pending')
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at   = db.Column(db.DateTime)

    tenant_name    = db.Column(db.String(120), default="")
    tenant_phone   = db.Column(db.String(20), default="")
    notifications = db.relationship('Notification', backref='resident', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        apt = Apartment.query.get(self.apartment_id) if self.apartment_id else None
        res = Residence.query.get(self.residence_id)
        return {
            'id': self.id, 'first_name': self.first_name, 'last_name': self.last_name,
            'full_name': f'{self.first_name} {self.last_name}',
            'cin': self.cin, 'phone': self.phone or '', 'email': self.email,
            'country': self.country or 'المغرب', 'floor': self.floor,
            'apt_number': self.apt_number or (apt.number if apt else '—'),
            'residence_id': self.residence_id,
            'residence_name': res.name if res else '?',
            'apartment_id': self.apartment_id, 'status': self.status,
            'created_at': self.created_at.strftime('%d/%m/%Y %H:%M'),
        }


# ══════════════════════════════════════════
#  NOTIFICATION
# ══════════════════════════════════════════
class Notification(db.Model):
    __tablename__ = 'notifications'
    id          = db.Column(db.Integer, primary_key=True)
    resident_id = db.Column(db.Integer, db.ForeignKey('residents.id'), nullable=False)
    title       = db.Column(db.String(120), nullable=False)
    body        = db.Column(db.Text)
    type        = db.Column(db.String(30), default='info')
    read        = db.Column(db.Boolean, default=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'title': self.title, 'body': self.body or '',
            'type': self.type, 'read': self.read,
            'created_at': self.created_at.strftime('%d/%m/%Y %H:%M'),
        }


# ══════════════════════════════════════════
#  ASSEMBLY — الجمع العام
# ══════════════════════════════════════════
class Assembly(db.Model):
    __tablename__ = 'assemblies'
    id           = db.Column(db.Integer, primary_key=True)
    residence_id = db.Column(db.Integer, db.ForeignKey('residences.id'), nullable=False)
    title        = db.Column(db.String(200), nullable=False)
    description  = db.Column(db.Text)
    date         = db.Column(db.DateTime, nullable=False)
    location     = db.Column(db.String(200))
    status       = db.Column(db.String(20), default='upcoming')  # upcoming|open|closed
    attendees    = db.Column(db.Text)
    absentees    = db.Column(db.Text)
    president    = db.Column(db.String(200))
    decisions    = db.Column(db.Text)
    report_notes = db.Column(db.Text)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    votes = db.relationship('Vote', backref='assembly', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id, 'residence_id': self.residence_id,
            'title': self.title, 'description': self.description or '',
            'date': self.date.strftime('%d/%m/%Y %H:%M'),
            'location': self.location or '', 'status': self.status,
            'created_at': self.created_at.strftime('%d/%m/%Y'),
            'votes_count': len(self.votes),
            'attendees': self.attendees or '',
            'absentees': self.absentees or '',
            'president': self.president or '',
            'decisions': self.decisions or '',
            'report_notes': self.report_notes or '',
        }


# ══════════════════════════════════════════
#  VOTE — تصويت
# ══════════════════════════════════════════
class Vote(db.Model):
    __tablename__ = 'votes'
    id          = db.Column(db.Integer, primary_key=True)
    assembly_id = db.Column(db.Integer, db.ForeignKey('assemblies.id'), nullable=False)
    question    = db.Column(db.String(300), nullable=False)
    yes_count   = db.Column(db.Integer, default=0)
    no_count    = db.Column(db.Integer, default=0)
    abstain     = db.Column(db.Integer, default=0)
    status      = db.Column(db.String(20), default='open')  # open|closed
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    responses = db.relationship('VoteResponse', backref='vote', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        total = self.yes_count + self.no_count + self.abstain
        return {
            'id': self.id, 'assembly_id': self.assembly_id,
            'question': self.question, 'yes_count': self.yes_count,
            'no_count': self.no_count, 'abstain': self.abstain,
            'total': total, 'status': self.status,
            'created_at': self.created_at.strftime('%d/%m/%Y %H:%M'),
        }


# ══════════════════════════════════════════
#  VOTE RESPONSE — استجابة التصويت
# ══════════════════════════════════════════
class VoteResponse(db.Model):
    __tablename__ = 'vote_responses'
    id          = db.Column(db.Integer, primary_key=True)
    vote_id     = db.Column(db.Integer, db.ForeignKey('votes.id'), nullable=False)
    resident_id = db.Column(db.Integer, db.ForeignKey('residents.id'), nullable=False)
    choice      = db.Column(db.String(10), nullable=False)  # yes|no|abstain
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)


# ══════════════════════════════════════════
#  DOCUMENT — وثيقة
# ══════════════════════════════════════════
class Document(db.Model):
    __tablename__ = 'documents'
    id           = db.Column(db.Integer, primary_key=True)
    residence_id = db.Column(db.Integer, db.ForeignKey('residences.id'), nullable=False)
    title        = db.Column(db.String(200), nullable=False)
    category     = db.Column(db.String(50), default='عام')  # عقد|محضر|وثيقة رسمية|عام
    file_path    = db.Column(db.String(300))
    file_name    = db.Column(db.String(200))
    is_public    = db.Column(db.Boolean, default=True)  # visible to residents
    uploaded_by  = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'residence_id': self.residence_id,
            'title': self.title, 'category': self.category,
            'file_path': self.file_path or '', 'file_name': self.file_name or '',
            'is_public': self.is_public,
            'created_at': self.created_at.strftime('%d/%m/%Y %H:%M'),
        }


# ══════════════════════════════════════════
#  RESERVE FUND — صندوق الاحتياط
# ══════════════════════════════════════════
class ReserveFund(db.Model):
    __tablename__ = 'reserve_fund'
    id           = db.Column(db.Integer, primary_key=True)
    residence_id = db.Column(db.Integer, db.ForeignKey('residences.id'), nullable=False, unique=True)
    balance      = db.Column(db.Float, default=0.0)
    target       = db.Column(db.Float, default=0.0)
    description  = db.Column(db.Text)
    updated_at   = db.Column(db.DateTime, default=datetime.utcnow)

    transactions = db.relationship('FundTransaction', backref='fund', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id, 'residence_id': self.residence_id,
            'balance': self.balance, 'target': self.target,
            'description': self.description or '',
            'updated_at': self.updated_at.strftime('%d/%m/%Y %H:%M'),
            'percent': round((self.balance / self.target * 100) if self.target > 0 else 0, 1),
        }


# ══════════════════════════════════════════
#  FUND TRANSACTION — معاملة الصندوق
# ══════════════════════════════════════════
class FundTransaction(db.Model):
    __tablename__ = 'fund_transactions'
    id       = db.Column(db.Integer, primary_key=True)
    fund_id  = db.Column(db.Integer, db.ForeignKey('reserve_fund.id'), nullable=False)
    amount   = db.Column(db.Float, nullable=False)
    type     = db.Column(db.String(10), nullable=False)  # in|out
    note     = db.Column(db.String(200))
    date     = db.Column(db.Date, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'amount': self.amount, 'type': self.type,
            'note': self.note or '', 'date': self.date.isoformat() if self.date else '',
            'created_at': self.created_at.strftime('%d/%m/%Y'),
        }


# ══════════════════════════════════════════
#  ANNOUNCEMENT — إعلان
# ══════════════════════════════════════════
class Announcement(db.Model):
    __tablename__ = 'announcements'
    id           = db.Column(db.Integer, primary_key=True)
    residence_id = db.Column(db.Integer, db.ForeignKey('residences.id'), nullable=False)
    title        = db.Column(db.String(200), nullable=False)
    body         = db.Column(db.Text)
    type         = db.Column(db.String(20), default='info')  # info|warning|urgent
    created_by   = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'residence_id': self.residence_id,
            'title': self.title, 'body': self.body or '', 'type': self.type,
            'created_at': self.created_at.strftime('%d/%m/%Y %H:%M'),
        }



# ══════════════════════════════════════════
#  ONLINE PAYMENT REQUEST — طلب الأداء الإلكتروني
# ══════════════════════════════════════════
class OnlinePaymentRequest(db.Model):
    __tablename__ = 'online_payment_requests'
    id           = db.Column(db.Integer, primary_key=True)
    resident_id  = db.Column(db.Integer, db.ForeignKey('residents.id'), nullable=False)
    apartment_id = db.Column(db.Integer, db.ForeignKey('apartments.id'), nullable=False)
    month        = db.Column(db.Integer, nullable=False)
    year         = db.Column(db.Integer, nullable=False)
    amount       = db.Column(db.Float, nullable=False)
    method       = db.Column(db.String(30), nullable=False)   # paypal|cmi|virement|qr
    status       = db.Column(db.String(20), default='pending') # pending|confirmed|rejected
    tx_ref       = db.Column(db.String(100))   # référence transaction
    proof_path   = db.Column(db.String(300))   # reçu image/PDF
    note         = db.Column(db.String(300))
    batch_id       = db.Column(db.String(40), nullable=False)
    reviewed_by  = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reviewed_at  = db.Column(db.DateTime)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        r   = Resident.query.get(self.resident_id)
        apt = Apartment.query.get(self.apartment_id)
        res = Residence.query.get(apt.residence_id) if apt else None
        MONTHS_AR = ['يناير','فبراير','مارس','أبريل','ماي','يونيو',
                     'يوليوز','غشت','شتنبر','أكتوبر','نونبر','دجنبر']
        method_label = {
            'paypal':'PayPal 💙','cmi':'بطاقة بنكية CMI 💳',
            'virement':'تحويل بنكي 🏦','qr':'QR Code 📱'
        }.get(self.method, self.method)
        return {
            'id': self.id,
            'resident_name': f'{r.first_name} {r.last_name}' if r else '?',
            'resident_email': r.email if r else '',
            'apt_number': apt.number if apt else '?',
            'residence_name': res.name if res else '?',
            'month': self.month, 'year': self.year,
            'month_label': f'{MONTHS_AR[(self.month or 1)-1]} {self.year}',
            'amount': self.amount,
            'method': self.method, 'method_label': method_label,
            'status': self.status,
            'tx_ref': self.tx_ref or '',
            'proof_path': self.proof_path or '',
            'note': self.note or '',
            'reviewed_at': self.reviewed_at.strftime('%d/%m/%Y %H:%M') if self.reviewed_at else None,
            'created_at': self.created_at.strftime('%d/%m/%Y %H:%M'),
        }

# ══════════════════════════════════════════
#  SUPPORT TICKET — تذكرة الدعم
# ══════════════════════════════════════════
class SupportTicket(db.Model):
    __tablename__ = 'support_tickets'
    id          = db.Column(db.Integer, primary_key=True)
    syndic_id   = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category    = db.Column(db.String(30), default='other')  # support|technical|info|other
    title       = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status      = db.Column(db.String(20), default='open')   # open|progress|closed
    admin_reply = db.Column(db.Text)
    replied_at  = db.Column(db.DateTime)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        syndic = User.query.get(self.syndic_id)
        cat_labels = {
            'support':   '🆘 طلب دعم',
            'technical': '🔧 مشكل تقني',
            'info':      'ℹ️ طلب معلومة',
            'other':     '📝 أخرى'
        }
        stat_labels = {'open':'مفتوحة','progress':'قيد المعالجة','closed':'مغلقة'}
        return {
            'id':           self.id,
            'syndic_id':    self.syndic_id,
            'syndic_name':  syndic.full_name if syndic else '?',
            'syndic_phone': syndic.phone if syndic else '',
            'syndic_city':  syndic.city if syndic else '',
            'category':     self.category,
            'category_label': cat_labels.get(self.category, self.category),
            'title':        self.title,
            'description':  self.description or '',
            'status':       self.status,
            'status_label': stat_labels.get(self.status, self.status),
            'admin_reply':  self.admin_reply or '',
            'replied_at':   self.replied_at.strftime('%d/%m/%Y %H:%M') if self.replied_at else '',
            'created_at':   self.created_at.strftime('%d/%m/%Y %H:%M'),
        }


# ══════════════════════════════════════════
#  GLOBAL NOTIFICATION (Admin → All Syndics)
# ══════════════════════════════════════════
class GlobalNotification(db.Model):
    __tablename__ = 'global_notifications'
    id         = db.Column(db.Integer, primary_key=True)
    title      = db.Column(db.String(120), nullable=False)
    body       = db.Column(db.Text)
    type       = db.Column(db.String(30), default='info')
    target     = db.Column(db.String(30), default='all')  # all|active|pending
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'title': self.title, 'body': self.body or '',
            'type': self.type, 'target': self.target,
            'created_at': self.created_at.strftime('%d/%m/%Y %H:%M'),
        }


# ══════════════════════════════════════════
#  PASSWORD RESET TOKEN — رمز إعادة التعيين
# ══════════════════════════════════════════
class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'
    id         = db.Column(db.Integer, primary_key=True)
    user_type  = db.Column(db.String(20), nullable=False)   # resident | syndic
    user_id    = db.Column(db.Integer, nullable=False)
    token      = db.Column(db.String(10), nullable=False)
    method     = db.Column(db.String(10), nullable=False)   # email | phone
    used       = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ══════════════════════════════════════════
#  ADMIN SETTINGS — إعدادات الأدمين
# ══════════════════════════════════════════
class AdminSettings(db.Model):
    __tablename__ = 'admin_settings'
    id              = db.Column(db.Integer, primary_key=True)
    # معلومات الأداء
    bank_name       = db.Column(db.String(100), default='CIH Bank')
    bank_rib        = db.Column(db.String(50),  default='')
    bank_owner      = db.Column(db.String(100), default='SyndikPro SARL')
    paypal_email    = db.Column(db.String(120), default='payments@syndikpro.ma')
    paypal_link     = db.Column(db.String(200), default='')
    # خدمة العملاء
    support_phone   = db.Column(db.String(30),  default='')
    support_whatsapp= db.Column(db.String(30),  default='')
    support_email   = db.Column(db.String(120), default='support@syndikpro.ma')
    support_hours   = db.Column(db.String(100), default='من الاثنين إلى الجمعة 9h-18h')
    # رسالة ترحيب للسانديك
    welcome_message = db.Column(db.Text, default='')
    # آخر تحديث
    updated_at      = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':              self.id,
            'bank_name':       self.bank_name or '',
            'bank_rib':        self.bank_rib or '',
            'bank_owner':      self.bank_owner or '',
            'paypal_email':    self.paypal_email or '',
            'paypal_link':     self.paypal_link or '',
            'support_phone':   self.support_phone or '',
            'support_whatsapp':self.support_whatsapp or '',
            'support_email':   self.support_email or '',
            'support_hours':   self.support_hours or '',
            'welcome_message': self.welcome_message or '',
            'updated_at':      self.updated_at.strftime('%d/%m/%Y %H:%M') if self.updated_at else '',
        }


# ══════════════════════════════════════════════════
#  PLATFORM SETTINGS — إعدادات المنصة المركزية
# ══════════════════════════════════════════════════
class PlatformSettings(db.Model):
    __tablename__ = 'platform_settings'
    id              = db.Column(db.Integer, primary_key=True)
    key             = db.Column(db.String(100), unique=True, nullable=False)
    value           = db.Column(db.Text, default='')
    label           = db.Column(db.String(200))
    category        = db.Column(db.String(50), default='payment')  # payment|support|general
    updated_at      = db.Column(db.DateTime, default=datetime.utcnow)
    updated_by      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def to_dict(self):
        return {
            'id':         self.id,
            'key':        self.key,
            'value':      self.value or '',
            'label':      self.label or self.key,
            'category':   self.category,
            'updated_at': self.updated_at.strftime('%d/%m/%Y %H:%M') if self.updated_at else '',
        }


# ══════════════════════════════════════════
#  NEIGHBOR POST — إعلانات الجيران
# ══════════════════════════════════════════
class NeighborPost(db.Model):
    __tablename__ = 'neighbor_posts'
    id           = db.Column(db.Integer, primary_key=True)
    residence_id = db.Column(db.Integer, db.ForeignKey('residences.id'), nullable=False)
    resident_id  = db.Column(db.Integer, db.ForeignKey('residents.id'), nullable=False)
    type         = db.Column(db.String(20), default='sell')  # sell|rent|service|lost
    title        = db.Column(db.String(200), nullable=False)
    description  = db.Column(db.Text)
    phone        = db.Column(db.String(20))
    city         = db.Column(db.String(80))
    is_active    = db.Column(db.Boolean, default=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    scope        = db.Column(db.String(20), default='private')
    contact_name = db.Column(db.String(100))
    author_name  = db.Column(db.String(100))
    images       = db.Column(db.Text)

    def to_dict(self, me_id=None):
        import json
        imgs = []
        if self.images:
            try: imgs = json.loads(self.images)
            except: imgs = []
        return {
            'id': self.id,
            'residence_id': self.residence_id,
            'type': self.type,
            'title': self.title,
            'description': self.description or '',
            'body': self.description or '',
            'city': self.city or '',
            'phone': self.phone or '',
            'scope': self.scope or 'private',
            'author_name': self.author_name or self.contact_name or '',
            'images': imgs,
            'is_active': self.is_active,
            'is_owner': (self.resident_id == me_id) if me_id is not None else False,
            'apartment_number': '',
            'created_at': self.created_at.strftime('%d/%m/%Y %H:%M'),
        }


# ================================
#  NEIGHBOR POST MESSAGE — دردشة خاصة بخصوص إعلان
# ================================
class NeighborPostMessage(db.Model):
    __tablename__ = 'neighbor_post_messages'
    id                   = db.Column(db.Integer, primary_key=True)
    post_id              = db.Column(db.Integer, db.ForeignKey('neighbor_posts.id'), nullable=False)
    sender_resident_id   = db.Column(db.Integer, db.ForeignKey('residents.id'), nullable=False)
    receiver_resident_id = db.Column(db.Integer, db.ForeignKey('residents.id'), nullable=False)
    message              = db.Column(db.Text, nullable=False)
    is_read              = db.Column(db.Boolean, default=False)
    created_at           = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self, me_id=None):
        return {
            'id': self.id,
            'post_id': self.post_id,
            'mine': (self.sender_resident_id == me_id) if me_id is not None else None,
            'message': self.message,
            'is_read': self.is_read,
            'created_at': self.created_at.strftime('%d/%m/%Y %H:%M'),
        }


# ══════════════════════════════════════════
#  ANNOUNCEMENT DISMISSAL TRACKING
# ══════════════════════════════════════════
class AnnouncementDismissal(db.Model):
    __tablename__ = 'announcement_dismissals'
    id               = db.Column(db.Integer, primary_key=True)
    resident_id      = db.Column(db.Integer, db.ForeignKey('residents.id'), nullable=False)
    announcement_id  = db.Column(db.Integer, db.ForeignKey('announcements.id'), nullable=False)
    dismissed_at     = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('resident_id', 'announcement_id', name='unique_dismiss'),)




class DailyFact(db.Model):
    __tablename__ = 'daily_facts'
    id = db.Column(db.Integer, primary_key=True)
    fact_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def to_dict(self):
        return {'id': self.id, 'fact_text': self.fact_text}

# ══════════════════════════════════════════
#  SUBSCRIPTION REQUEST - طلب الاشتراك
# ══════════════════════════════════════════
class SubscriptionRequest(db.Model):
    __tablename__ = 'subscription_requests'
    id                = db.Column(db.Integer, primary_key=True)
    user_id           = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    plan_id           = db.Column(db.Integer, db.ForeignKey('subscription_plans.id'), nullable=False)
    months            = db.Column(db.Integer, default=1)
    base_price        = db.Column(db.Float)      # السعر الأساسي
    discount_percent  = db.Column(db.Float, default=0)
    discount_amount   = db.Column(db.Float, default=0)
    final_price       = db.Column(db.Float)
    status            = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    requested_at      = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at       = db.Column(db.DateTime)
    approved_by       = db.Column(db.Integer)
    notes             = db.Column(db.Text)
    receipt_path      = db.Column(db.String(255))
    payment_method    = db.Column(db.String(50))
    receipt_path      = db.Column(db.String(255))
    payment_method    = db.Column(db.String(50))
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'plan_id': self.plan_id,
            'months': self.months,
            'base_price': self.base_price,
            'discount_percent': self.discount_percent,
            'discount_amount': self.discount_amount,
            'final_price': self.final_price,
            'status': self.status,
            'requested_at': self.requested_at.isoformat() if self.requested_at else None,
        }
