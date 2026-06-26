# SyndikPro — دليل النشر على PythonAnywhere
# ════════════════════════════════════════════

## الملفات
```
syndikpro/
├── app.py          ← Flask routes
├── models.py       ← SQLAlchemy models
├── init_db.py      ← إنشاء DB + مستخدم أول
├── wsgi.py         ← نقطة دخول PA
├── requirements.txt
├── templates/
│   └── index.html
└── static/
```

## خطوات النشر

### 1. رفع الملفات
```bash
# في Bash console على PythonAnywhere
mkdir ~/syndikpro
# ارفع الملفات عبر Files أو git
```

### 2. تثبيت المتطلبات
```bash
cd ~/syndikpro
pip install -r requirements.txt --user
```

### 3. إنشاء قاعدة البيانات
```bash
python init_db.py
# → مستخدم: admin / admin123
```

### 4. إعداد Web App في PA
- اذهب إلى Web tab
- Source code: `/home/USERNAME/syndikpro`
- WSGI file: انسخ محتوى wsgi.py
- Working directory: `/home/USERNAME/syndikpro`
- Static files: URL `/static/` → `/home/USERNAME/syndikpro/static/`

### 5. متغيرات البيئة (اختياري)
في WSGI file أضف:
```python
os.environ['SECRET_KEY'] = 'مفتاح-سري-قوي-هنا'
```

### 6. Reload وافتح التطبيق
- اضغط Reload
- افتح: https://USERNAME.pythonanywhere.com

## تسجيل الدخول الأول
- المستخدم: `admin`
- كلمة المرور: `admin123`
- غيّرها فوراً من إعدادات الحساب!

## API Routes
```
POST /api/login                          تسجيل الدخول
POST /api/logout                         الخروج
GET  /api/me                             بيانات المستخدم الحالي

GET/POST /api/residences                 الإقامات
PUT/DELETE /api/residences/<id>

GET/POST /api/residences/<id>/apartments الشقق
GET/PUT/DELETE /api/apartments/<id>
POST /api/apartments                     إضافة شقة

GET  /api/residences/<id>/payments       المدفوعات
POST /api/payments                       تسجيل دفعة
DELETE /api/payments/<id>

GET  /api/residences/<id>/complaints     الشكايات
POST /api/complaints
PUT/DELETE /api/complaints/<id>

GET  /api/residences/<id>/expenses       المصاريف
POST /api/expenses
DELETE /api/expenses/<id>

GET  /api/residences/<id>/stats          إحصائيات Dashboard
```
