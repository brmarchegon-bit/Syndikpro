from flask import Blueprint, request, jsonify, session
import json, os, threading
from datetime import datetime

payment_bp = Blueprint("payment", __name__)

BASE_DIR      = os.environ.get("BASE_DIR", "/home/Hicham/syndikpro")
PAYMENT_FILE  = os.path.join(BASE_DIR, "payment_info.json")
_payment_lock = threading.Lock()

DEFAULT_PAYMENT_INFO = {
    "bank_name":       "",
    "account_number":  "",
    "rib":             "",
    "iban":            "",
    "account_owner":   "المديرية الإقليمية إنزكان آيت ملول",
    "payment_note":    "",
    "official_email":  "",
    "support_phone":   "",
    "support_phone2":  "",
    "office_address":  "المديرية الإقليمية للتربية والتعليم، إنزكان آيت ملول",
    "office_hours":    "الاثنين – الجمعة: 8:30 – 16:30",
    "last_updated":    "",
    "updated_by":      "",
}

def load_payment_info():
    if os.path.exists(PAYMENT_FILE):
        with open(PAYMENT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {**DEFAULT_PAYMENT_INFO, **data}
    return dict(DEFAULT_PAYMENT_INFO)

def save_payment_info(data):
    with _payment_lock:
        with open(PAYMENT_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")

def _is_admin():
    return session.get("user") == ADMIN_USER

def _is_logged():
    return bool(session.get("user"))

@payment_bp.route("/api/payment_info", methods=["GET"])
def api_get_payment_info():
    if not _is_logged():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(load_payment_info())

@payment_bp.route("/api/payment_info", methods=["POST"])
def api_set_payment_info():
    if not _is_admin():
        return jsonify({"error": "unauthorized"}), 401
    token = (request.get_json(silent=True) or {}).get("_csrf") or \
            request.headers.get("X-CSRF-Token")
    if not token or token != session.get("csrf_token"):
        return jsonify({"error": "طلب غير صالح (CSRF)"}), 403
    data = request.get_json()
    info = load_payment_info()
    ALLOWED_FIELDS = {
        "bank_name","account_number","rib","iban","account_owner",
        "payment_note","official_email","support_phone","support_phone2",
        "office_address","office_hours",
    }
    for field in ALLOWED_FIELDS:
        if field in data:
            val = str(data[field]).strip()
            val = val.replace("<","&lt;").replace(">","&gt;")
            info[field] = val
    info["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    info["updated_by"]   = session.get("user","")
    save_payment_info(info)
    return jsonify({"ok": True, "msg": "تم حفظ المعلومات بنجاح"})
