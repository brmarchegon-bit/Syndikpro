"""
Image Security Module - دالة مركزية آمنة لضغط وتصغير الصور
"""

import os
from PIL import Image
from io import BytesIO
import hashlib
import time
from werkzeug.utils import secure_filename

ALLOWED_FORMATS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_IMAGE_WIDTH = 3000
MAX_IMAGE_HEIGHT = 3000
MIN_WIDTH = 100
MIN_HEIGHT = 100

def secure_compress_image(file_obj, upload_folder, filename_prefix='img', quality=85, max_width=1920, max_height=1920):
    """ضغط وتصغير الصورة بأمان كامل"""
    
    result = {'success': False, 'filename': None, 'path': None, 'error': None}
    
    try:
        if not file_obj or not file_obj.filename:
            result['error'] = 'لا يوجد ملف'
            return result
        
        filename = file_obj.filename.strip()
        if '.' not in filename:
            result['error'] = 'الملف بدون امتداد'
            return result
        
        file_ext = filename.rsplit('.', 1)[1].lower()
        if file_ext not in ALLOWED_FORMATS:
            result['error'] = f'صيغة الملف غير مسموحة: {file_ext}'
            return result
        
        # فحص الامتدادات المزدوجة
        parts = filename.lower().split('.')
        dangerous_exts = ['php', 'py', 'js', 'sh', 'exe', 'bat', 'cmd', 'asp', 'jsp', 'html', 'svg']
        if len(parts) > 2:
            for part in parts[:-1]:
                if part in dangerous_exts:
                    result['error'] = 'محاولة رفع ملف خطير (امتداد مزدوج)'
                    return result
        
        file_content = file_obj.read()
        file_obj.seek(0)
        
        if not file_content:
            result['error'] = 'الملف فارغ'
            return result
        
        file_size = len(file_content)
        if file_size > MAX_FILE_SIZE:
            result['error'] = f'حجم الملف كبير جداً'
            return result
        
        if file_size < 100:
            result['error'] = 'الملف صغير جداً'
            return result
        
        # فتح الصورة والتحقق من صحتها
        try:
            img = Image.open(BytesIO(file_content))
            img.verify()
            img = Image.open(BytesIO(file_content))
        except Exception as e:
            result['error'] = f'الملف ليس صورة صحيحة'
            return result
        
        width, height = img.size
        
        if width < MIN_WIDTH or height < MIN_HEIGHT:
            result['error'] = 'أبعاد الصورة صغيرة جداً'
            return result
        
        if width > MAX_IMAGE_WIDTH or height > MAX_IMAGE_HEIGHT:
            result['error'] = 'أبعاد الصورة كبيرة جداً'
            return result
        
        # تحويل صور RGBA إلى RGB
        if img.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            background.paste(img, mask=img.split()[-1] if img.mode in ('RGBA', 'LA') else None)
            img = background
        elif img.mode != 'RGB':
            img = img.convert('RGB')
        
        # تصغير الصورة
        if width > max_width or height > max_height:
            img.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
        
        # إنشاء اسم ملف آمن
        timestamp = int(time.time())
        hash_suffix = hashlib.md5(file_content).hexdigest()[:8]
        safe_name = secure_filename(filename_prefix)
        
        output_format = img.format.lower() if img.format else file_ext.lower()
        if output_format not in ALLOWED_FORMATS:
            output_format = 'jpg'
        
        new_filename = f"{timestamp}_{hash_suffix}_{safe_name}.{output_format}"
        file_path = os.path.join(upload_folder, new_filename)
        
        os.makedirs(upload_folder, exist_ok=True)
        
        # حفظ الصورة
        if output_format == 'png':
            img.save(file_path, 'PNG', optimize=True)
        elif output_format == 'gif':
            img.save(file_path, 'GIF', optimize=True)
        elif output_format == 'webp':
            img.save(file_path, 'WEBP', quality=quality)
        else:
            img.save(file_path, 'JPEG', quality=quality, optimize=True)
        
        if not os.path.exists(file_path):
            result['error'] = 'فشل حفظ الملف'
            return result
        
        final_size = os.path.getsize(file_path)
        if final_size == 0:
            os.remove(file_path)
            result['error'] = 'الملف المحفوظ فارغ'
            return result
        
        result['success'] = True
        result['filename'] = new_filename
        result['path'] = f'static/uploads/{new_filename}'
        result['original_size'] = file_size
        result['compressed_size'] = final_size
        result['compression_ratio'] = round((1 - final_size/file_size) * 100, 2)
        
        return result
    
    except Exception as e:
        result['error'] = f'خطأ: {str(e)}'
        return result

def verify_image_safety(file_path):
    """التحقق من أمان صورة موجودة"""
    if not os.path.exists(file_path):
        return False, 'الملف غير موجود'
    
    try:
        img = Image.open(file_path)
        img.verify()
        return True, 'الصورة آمنة'
    except Exception as e:
        return False, f'خطأ التحقق: {str(e)}'

def cleanup_old_images(upload_folder, days=30):
    """حذف الصور الأقدم من عدد معين من الأيام"""
    if not os.path.exists(upload_folder):
        return 0
    
    current_time = time.time()
    deleted_count = 0
    
    for filename in os.listdir(upload_folder):
        file_path = os.path.join(upload_folder, filename)
        if os.path.isfile(file_path):
            file_age = current_time - os.path.getmtime(file_path)
            if file_age > days * 24 * 3600:
                try:
                    os.remove(file_path)
                    deleted_count += 1
                except:
                    pass
    
    return deleted_count
