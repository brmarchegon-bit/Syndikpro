import os
from pathlib import Path

base_path = os.getcwd()

def show_tree(path, prefix="", max_depth=3, current_depth=0):
    if current_depth >= max_depth or not os.path.exists(path):
        return
    
    try:
        items = sorted(os.listdir(path))
    except:
        return
    
    skip = {'.git', '__pycache__', '.pytest_cache', 'node_modules', '.venv', 'venv', '.env', '__pycache__'}
    items = [i for i in items if i not in skip and not i.startswith('.')]
    
    for i, item in enumerate(items):
        item_path = os.path.join(path, item)
        is_last = i == len(items) - 1
        
        print(f"{prefix}{'└── ' if is_last else '├── '}{item}")
        
        if os.path.isdir(item_path):
            next_prefix = prefix + ("    " if is_last else "│   ")
            show_tree(item_path, next_prefix, max_depth, current_depth + 1)

print(f"\n📁 بنية المشروع من: {base_path}\n")
show_tree(base_path)

print("\n" + "="*60)
print("الملفات المهمة:")
for f in ['app.py', 'models.py', 'syndik.db', 'requirements.txt']:
    exists = "✅" if os.path.exists(f) else "❌"
    print(f"{exists} {f}")
