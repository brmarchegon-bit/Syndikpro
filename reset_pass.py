from app import app, db
from models import User
from werkzeug.security import generate_password_hash
with app.app_context():
    u = User.query.filter_by(username='hicham').first()
    u.password_hash = generate_password_hash('1234')
    db.session.commit()
    print('OK - كلمة المرور الجديدة: 1234')
