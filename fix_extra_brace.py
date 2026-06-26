# -*- coding: utf-8 -*-
"""
يُصحّح خطأ القوس الزائدة فـ scripts_core.html.
السبب: الكود الجديد زاد '}' فنهاية submitResPaymentNew، بينما
الكود القديم (تحويل الأشهر / toast / setTimeout) بقي جزءاً من نفس
الدالة، فأصبحت '}' فسطر setTimeout زائدة بلا فتح مطابق.
الحل: حذف '}' الزائدة بعد await fetch(...) مباشرة، باش يبقى الإغلاق
الحقيقي هو الموجود فنهاية setTimeout(...).
"""
import io

TARGET = "/home/Hicham/syndikpro/templates/partials/scripts_core.html"

OLD = "await fetch('/api/resident/pay',{method:'POST',body:fd,credentials:'include'});}\n// تحويل الأشهر للأصفر فوراً بدون انتظار reload"
NEW = "await fetch('/api/resident/pay',{method:'POST',body:fd,credentials:'include'});\n// تحويل الأشهر للأصفر فوراً بدون انتظار reload"


def main():
    with io.open(TARGET, "r", encoding="utf-8") as fh:
        content = fh.read()

    count = content.count(OLD)
    if count != 1:
        print(f"ERROR: عدد التطابقات = {count} (متوقع 1). لم يتم أي تعديل.")
        return

    content = content.replace(OLD, NEW, 1)

    with io.open(TARGET, "w", encoding="utf-8") as fh:
        fh.write(content)

    print("OK: تم حذف القوس الزائدة بنجاح.")


if __name__ == "__main__":
    main()
