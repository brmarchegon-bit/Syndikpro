# -*- coding: utf-8 -*-
"""
هذا السكريبت يُعدّل route الدفع فـ app.py باش يقبل عدة أشهر دفعة واحدة.
يُنفَّذ على السيرفر ديال PythonAnywhere، فالمسار /home/Hicham/syndikpro/
"""
import io

APP_PY = "/home/Hicham/syndikpro/app.py"

OLD_BLOCK = '''@app.route('/api/resident/pay', methods=['POST'])
@resident_required
def resident_submit_payment():
    r = get_current_resident()
    if not r or not r.apartment_id:
        return jsonify({'error': 'لم يتم تعيين شقة لك بعد'}), 400

    method = request.form.get('method', '')
    month  = int(request.form.get('month', 0))
    year   = int(request.form.get('year', 0))
    amount = float(request.form.get('amount', 0))
    tx_ref = request.form.get('tx_ref', '').strip()
    note   = request.form.get('note', '').strip()

    if not all([method, month, year, amount]):
        return jsonify({'error': 'بيانات ناقصة'}), 400

    # تحقق من عدم وجود طلب معلق
    existing = OnlinePaymentRequest.query.filter_by(
        apartment_id=r.apartment_id, month=month, year=year, status='pending'
    ).first()
    if existing:
        return jsonify({'error': 'يوجد طلب أداء معلق لهذا الشهر'}), 400

    proof_path = ''
    if 'proof' in request.files:
        f = request.files['proof']
        if f and f.filename and allowed_file(f.filename):
            from werkzeug.utils import secure_filename
            import time
            fn = f"{int(time.time())}_{secure_filename(f.filename)}"
            fp = os.path.join(app.config['UPLOAD_FOLDER'], fn)
            f.save(fp)
            proof_path = f'static/uploads/{fn}'

    req = OnlinePaymentRequest(
        resident_id=r.id,
        apartment_id=r.apartment_id,
        month=month, year=year, amount=amount,
        method=method, tx_ref=tx_ref, note=note,
        proof_path=proof_path, status='pending'
    )
    db.session.add(req)
    db.session.commit()

    # إشعار للساكن
    notif = Notification(
        resident_id=r.id,
        title='تم إرسال طلب الأداء',
        body=f'طلبك بمبلغ {amount} درهم عبر {method} قيد المراجعة من طرف السانديك.',
        type='info'
    )
    db.session.add(notif)
    db.session.commit()
    return jsonify({'ok': True, 'id': req.id})'''

NEW_BLOCK = '''@app.route('/api/resident/pay', methods=['POST'])
@resident_required
def resident_submit_payment():
    r = get_current_resident()
    if not r or not r.apartment_id:
        return jsonify({'error': 'لم يتم تعيين شقة لك بعد'}), 400

    import uuid as _uuid

    method = request.form.get('method', '')
    tx_ref = request.form.get('tx_ref', '').strip()
    note   = request.form.get('note', '').strip()

    # دعم دفعة لعدة أشهر: months_json = [{"month":1,"year":2026,"amount":300}, ...]
    # مع الحفاظ على التوافقية مع الإرسال القديم (شهر واحد: month/year/amount)
    months_json = request.form.get('months_json', '').strip()
    items = []
    if months_json:
        import json as _json
        try:
            raw_items = _json.loads(months_json)
        except Exception:
            return jsonify({'error': 'صيغة الأشهر غير صحيحة'}), 400
        for it in raw_items:
            try:
                m = int(it.get('month', 0))
                y = int(it.get('year', 0))
                a = float(it.get('amount', 0))
            except Exception:
                return jsonify({'error': 'بيانات ناقصة'}), 400
            if not all([m, y, a]):
                return jsonify({'error': 'بيانات ناقصة'}), 400
            items.append({'month': m, 'year': y, 'amount': a})
    else:
        month  = int(request.form.get('month', 0))
        year   = int(request.form.get('year', 0))
        amount = float(request.form.get('amount', 0))
        if not all([method, month, year, amount]):
            return jsonify({'error': 'بيانات ناقصة'}), 400
        items = [{'month': month, 'year': year, 'amount': amount}]

    if not method or not items:
        return jsonify({'error': 'بيانات ناقصة'}), 400

    # تحقق من عدم وجود طلب معلق لأي شهر من الأشهر المطلوبة (قبل إنشاء أي سجل)
    for it in items:
        existing = OnlinePaymentRequest.query.filter_by(
            apartment_id=r.apartment_id, month=it['month'], year=it['year'], status='pending'
        ).first()
        if existing:
            return jsonify({'error': f"يوجد طلب أداء معلق لشهر {it['month']}/{it['year']}"}), 400

    proof_path = ''
    if 'proof' in request.files:
        f = request.files['proof']
        if f and f.filename and allowed_file(f.filename):
            from werkzeug.utils import secure_filename
            import time
            fn = f"{int(time.time())}_{secure_filename(f.filename)}"
            fp = os.path.join(app.config['UPLOAD_FOLDER'], fn)
            f.save(fp)
            proof_path = f'static/uploads/{fn}'

    batch_id = _uuid.uuid4().hex[:32] if len(items) > 1 else None
    total_amount = 0.0
    created_ids = []

    for it in items:
        req = OnlinePaymentRequest(
            resident_id=r.id,
            apartment_id=r.apartment_id,
            month=it['month'], year=it['year'], amount=it['amount'],
            method=method, tx_ref=tx_ref, note=note,
            proof_path=proof_path, status='pending',
            batch_id=batch_id
        )
        db.session.add(req)
        db.session.flush()
        created_ids.append(req.id)
        total_amount += it['amount']

    db.session.commit()

    # إشعار واحد فقط للساكن، يجمع كل الدفعة
    if len(items) > 1:
        body = f'طلبك بمبلغ {total_amount} درهم عبر {method} لعدد {len(items)} أشهر قيد المراجعة من طرف السانديك.'
    else:
        body = f'طلبك بمبلغ {total_amount} درهم عبر {method} قيد المراجعة من طرف السانديك.'

    notif = Notification(
        resident_id=r.id,
        title='تم إرسال طلب الأداء',
        body=body,
        type='info'
    )
    db.session.add(notif)
    db.session.commit()

    return jsonify({'ok': True, 'ids': created_ids, 'batch_id': batch_id})'''


def main():
    with io.open(APP_PY, "r", encoding="utf-8") as fh:
        content = fh.read()

    count = content.count(OLD_BLOCK)
    if count != 1:
        print(f"ERROR: عدد التطابقات = {count} (متوقع 1). لم يتم أي تعديل.")
        return

    content = content.replace(OLD_BLOCK, NEW_BLOCK, 1)

    with io.open(APP_PY, "w", encoding="utf-8") as fh:
        fh.write(content)

    print("OK: تم تعديل route /api/resident/pay بنجاح.")


if __name__ == "__main__":
    main()
