import ast, glob

def get_routes(filename):
    with open(filename, encoding='utf-8') as f:
        source = f.read()
    tree = ast.parse(source, filename=filename)
    routes = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                    if dec.func.attr == 'route' and dec.args:
                        arg0 = dec.args[0]
                        if isinstance(arg0, ast.Constant):
                            seg = ast.get_source_segment(source, node)
                            routes.setdefault(arg0.value, []).append((filename, node.name, seg))
    return routes

app_routes = get_routes('app.py')
bp_routes = {}
for fn in sorted(glob.glob('routes/*.py')):
    for path, items in get_routes(fn).items():
        bp_routes.setdefault(path, []).extend(items)

def norm(code):
    return '\n'.join(l.strip().replace('"', "'") for l in code.splitlines() if l.strip())

only_app = sorted(set(app_routes) - set(bp_routes))
only_bp = sorted(set(bp_routes) - set(app_routes))
common = sorted(set(app_routes) & set(bp_routes))

identical, different = [], []
for p in common:
    if norm(app_routes[p][0][2]) == norm(bp_routes[p][0][2]):
        identical.append(p)
    else:
        different.append(p)

print(f"app.py: {len(app_routes)} routes | blueprints: {len(bp_routes)} routes")
print(f"مشترك: {len(common)} | متطابق: {len(identical)} | مختلف: {len(different)}")
print(f"\n=== موجود غير فـ app.py (ناقص من blueprints) [{len(only_app)}] ===")
for p in only_app: print(" ", p)
print(f"\n=== موجود غير فـ blueprints (زيادة جديدة!) [{len(only_bp)}] ===")
for p in only_bp: print(" ", p)
print(f"\n=== route مختلفة بين النسختين [{len(different)}] ===")
for p in different: print(" ", p)
