"""
init_db.py — يُشغَّل مرة واحدة لإنشاء القاعدة والمستخدم الأول
python init_db.py
"""
from app import app, db
from models import User
from werkzeug.security import generate_password_hash

with app.app_context():
    db.create_all()

    # إنشاء مستخدم افتراضي إذا لم يكن موجودًا
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username      = 'admin',
            password_hash = generate_password_hash('admin123'),
            full_name     = 'المدير',
            role          = 'admin',
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ قاعدة البيانات جاهزة")
        print("👤 مستخدم: admin / admin123")
        print("⚠️  غيّر كلمة المرور بعد أول دخول!")
    else:
        print("✅ القاعدة موجودة مسبقاً")
