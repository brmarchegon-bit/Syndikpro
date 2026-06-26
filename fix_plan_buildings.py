#!/usr/bin/env python3
import sys

models_file = '/home/Hicham/syndikpro/models.py'
with open(models_file, 'r', encoding='utf-8') as f:
    content = f.read()

old_max_apartments = "    max_apartments = db.Column(db.Integer, default=20)"
new_max_apartments = "    max_apartments = db.Column(db.Integer, default=20)\n    max_buildings  = db.Column(db.Integer, default=6)"

if old_max_apartments in content:
    content = content.replace(old_max_apartments, new_max_apartments, 1)
    print("✅ Step 1: Added max_buildings")
else:
    print("❌ Not found")
    sys.exit(1)

old_to_dict = """    def to_dict(self):
        return {
            'id':             self.id,
            'name':           self.name,
            'label':          self.label or self.name,
            'price_monthly':  self.price_monthly,
            'max_residences': self.max_residences,
            'max_apartments': self.max_apartments,
            'features':       self.features or '',
            'is_active':      self.is_active,
        }"""

new_to_dict = """    def to_dict(self):
        return {
            'id':             self.id,
            'name':           self.name,
            'label':          self.label or self.name,
            'price_monthly':  self.price_monthly,
            'max_residences': self.max_residences,
            'max_buildings':  self.max_buildings,
            'max_apartments': self.max_apartments,
            'features':       self.features or '',
            'is_active':      self.is_active,
        }"""

if old_to_dict in content:
    content = content.replace(old_to_dict, new_to_dict, 1)
    print("✅ Step 2: Updated to_dict")
else:
    print("❌ to_dict not found")
    sys.exit(1)

with open(models_file, 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ models.py updated!")
