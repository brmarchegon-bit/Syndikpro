# -*- coding: utf-8 -*-
"""
يُعدّل function submitResPaymentNew فـ scripts_core.html
باش يبعت طلب POST واحد فيه months_json بدل loop منفصل لكل شهر.
يُنفَّذ على PythonAnywhere فالمسار /home/Hicham/syndikpro/
"""
import io

TARGET = "/home/Hicham/syndikpro/templates/partials/scripts_core.html"

# نعتمد على markers (بداية ونهاية الدالة) بدل تطابق نص حرفي كامل، لتجنب مشاكل الأحرف الخفية
START_MARKER = "async function submitResPaymentNew(method){"
END_MARKER = "await fetch('/api/resident/pay',{method:'POST',body:fd,credentials:'include'});}"

NEW = """async function submitResPaymentNew(method){if(resSelectedMonths.length===0){toast('اختر شهراً واحداً على الأقل');return;}
const total=resSelectedMonths.reduce((s,m)=>s+m.amount,0);
const sentMonths=[...resSelectedMonths];
const fd=new FormData();fd.append('method',method);
fd.append('months_json',JSON.stringify(sentMonths.map(m=>({month:m.month,year:m.year,amount:m.amount}))));
if(method==='virement'){const ref=document.getElementById('res-vir-ref')?.value.trim();if(!ref){toast('ادخل رقم المرجع');return;}fd.append('tx_ref',ref);}
if(method==='proof'||method==='virement'){const f=document.getElementById(method==='proof'?'res-proof-file':'res-proof-file-vir')?.files[0];if(f)fd.append('proof',f);}
await fetch('/api/resident/pay',{method:'POST',body:fd,credentials:'include'});}"""


def main():
    with io.open(TARGET, "r", encoding="utf-8") as fh:
        content = fh.read()

    start_idx = content.find(START_MARKER)
    if start_idx == -1:
        print("ERROR: لم يتم العثور على بداية الدالة (START_MARKER). لم يتم أي تعديل.")
        return

    end_idx = content.find(END_MARKER, start_idx)
    if end_idx == -1:
        print("ERROR: لم يتم العثور على نهاية الدالة (END_MARKER). لم يتم أي تعديل.")
        return

    end_idx += len(END_MARKER)

    old_block = content[start_idx:end_idx]
    print("---- الكتلة المستهدفة للحذف (للتأكيد) ----")
    print(old_block)
    print("---- نهاية الكتلة ----")

    content = content[:start_idx] + NEW + content[end_idx:]

    with io.open(TARGET, "w", encoding="utf-8") as fh:
        fh.write(content)

    print("OK: تم تعديل submitResPaymentNew بنجاح.")


if __name__ == "__main__":
    main()
