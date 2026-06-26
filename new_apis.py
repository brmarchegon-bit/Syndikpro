# APIs الاشتراكات الجديدة - سيتم إضافتها في نهاية app.py

# 1. API الخصومات
subscription_discounts_api = '''
@app.route('/api/subscription-discounts')
def get_subscription_discounts():
    try:
        discounts = SubscriptionDiscount.query.all()
        return jsonify([d.to_dict() for d in discounts])
    except Exception as e:
        return jsonify({'error': str(e)}), 500
'''

# 2. API إنشاء طلب الاشتراك
create_request_api = '''
@app.route('/api/subscriptions/request', methods=['POST'])
@login_required
def create_subscription_request():
    try:
        from datetime import timedelta
        u = get_current_user()
        plan_id = request.form.get('plan_id')
        months = int(request.form.get('months', 1))
        payment_method = request.form.get('payment_method', '')
        notes = request.form.get('notes', '')
        
        if not plan_id or not payment_method:
            return jsonify({'error': 'البيانات غير كاملة'}), 400
        
        plan_obj = SubscriptionPlan.query.get_or_404(plan_id)
        base_price = plan_obj.price_monthly * months
        discount = SubscriptionDiscount.query.filter(SubscriptionDiscount.min_months <= months).order_by(SubscriptionDiscount.discount_percent.desc()).first()
        discount_percent = discount.discount_percent if discount else 0
        discount_amount = base_price * (discount_percent / 100)
        final_price = base_price - discount_amount
        
        receipt_path = ''
        if 'receipt' in request.files:
            f = request.files['receipt']
            if not f:
                return jsonify({'error': '❌ لم يتم اختيار ملف'}), 400
            if not f.filename:
                return jsonify({'error': '❌ اسم الملف فارغ'}), 400
            if not allowed_file(f.filename):
                return jsonify({'error': '❌ صيغة الملف غير مسموحة (jpg, png, pdf فقط)'}), 400
            
            try:
                from werkzeug.utils import secure_filename
                import time
                fn = f"{int(time.time())}_{secure_filename(f.filename)}"
                fp = os.path.join(app.config['UPLOAD_FOLDER'], fn)
                os.makedirs(os.path.dirname(fp), exist_ok=True)
                f.save(fp)
                if not os.path.exists(fp):
                    return jsonify({'error': '❌ فشل حفظ الملف على الخادم'}), 500
                receipt_path = f'static/uploads/{fn}'
            except Exception as save_err:
                return jsonify({'error': f'❌ خطأ في حفظ الملف: {str(save_err)}'}), 500
        else:
            return jsonify({'error': '❌ الوصل (صورة الدفع) مطلوب'}), 400:
            return jsonify({'error': '❌ الوصل (صورة الدفع) مطلوب'}), 400
        
        sub_req = SubscriptionRequest(user_id=u.id, plan_id=plan_obj.id, months=months, base_price=base_price, discount_percent=discount_percent, discount_amount=discount_amount, final_price=final_price, status='pending', payment_method=payment_method, receipt_path=receipt_path, notes=notes)
        db.session.add(sub_req)
        admin_notif = GlobalNotification(title=f'💳 طلب اشتراك جديد — {u.full_name}', body=f'الخطة: {plan_obj.label} | المدة: {months} شهر | السعر: {final_price} د', type='subscription', target='admin')
        db.session.add(admin_notif)
        db.session.commit()
        return jsonify({'ok': True, 'request_id': sub_req.id, 'final_price': final_price})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
'''

# 3. API الإدمن - قائمة الطلبات
admin_list_api = '''
@app.route('/api/admin/subscription-requests')
@admin_required
def get_subscription_requests():
    try:
        status = request.args.get('status', '')
        query = SubscriptionRequest.query
        if status:
            query = query.filter_by(status=status)
        requests_list = query.order_by(SubscriptionRequest.requested_at.desc()).all()
        result = []
        for req in requests_list:
            user = User.query.get(req.user_id)
            plan = SubscriptionPlan.query.get(req.plan_id)
            result.append({'id': req.id, 'user_id': req.user_id, 'username': user.username if user else '?', 'full_name': user.full_name if user else '?', 'email': user.email if user else '?', 'plan_name': plan.label if plan else '?', 'months': req.months, 'base_price': req.base_price, 'discount_percent': req.discount_percent, 'discount_amount': req.discount_amount, 'final_price': req.final_price, 'payment_method': req.payment_method, 'receipt_path': req.receipt_path, 'status': req.status, 'notes': req.notes or '', 'requested_at': req.requested_at.isoformat() if req.requested_at else ''})
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
'''

# 4. API الإدمن - الموافقة
admin_approve_api = '''
@app.route('/api/admin/subscription-requests/<int:req_id>/approve', methods=['POST'])
@admin_required
def approve_subscription_request(req_id):
    try:
        from datetime import timedelta
        admin = get_current_user()
        sub_req = SubscriptionRequest.query.get_or_404(req_id)
        user = User.query.get_or_404(sub_req.user_id)
        plan = SubscriptionPlan.query.get_or_404(sub_req.plan_id)
        sub_req.status = 'approved'
        sub_req.approved_at = datetime.utcnow()
        sub_req.approved_by = admin.id
        user.subscription_confirmed = True
        user.plan = plan.name
        user.subscription_start = datetime.utcnow()
        user.subscription_end = datetime.utcnow() + timedelta(days=30 * sub_req.months)
        user.total_amount = sub_req.final_price
        user.duration_months = sub_req.months
        user.payment_method = sub_req.payment_method
        user.payment_date = datetime.utcnow()
        notif = Notification(user_id=user.id, title='✅ تمت الموافقة على الاشتراك!', body=f'تم تفعيل خطتك {plan.label} لمدة {sub_req.months} شهر', type='subscription')
        db.session.add(notif)
        db.session.commit()
        return jsonify({'ok': True, 'message': f'تمت الموافقة على طلب {user.full_name}', 'subscription_end': user.subscription_end.isoformat()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
'''

# 5. API الإدمن - الرفض
admin_reject_api = '''
@app.route('/api/admin/subscription-requests/<int:req_id>/reject', methods=['POST'])
@admin_required
def reject_subscription_request(req_id):
    try:
        admin = get_current_user()
        sub_req = SubscriptionRequest.query.get_or_404(req_id)
        user = User.query.get_or_404(sub_req.user_id)
        rejection_reason = request.json.get('reason', 'لم يتم تحديد السبب')
        sub_req.status = 'rejected'
        sub_req.approved_at = datetime.utcnow()
        sub_req.approved_by = admin.id
        sub_req.notes = f"رفض: {rejection_reason}"
        notif = Notification(user_id=user.id, title='❌ تم رفض طلب الاشتراك', body=f'السبب: {rejection_reason}', type='subscription')
        db.session.add(notif)
        db.session.commit()
        return jsonify({'ok': True, 'message': f'تم رفض طلب {user.full_name}'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
'''
