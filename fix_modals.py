import re

with open('./syndikpro/templates/partials/modals.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove duplicate modals - keep only first occurrence
modals_to_fix = ['mod-announce', 'mod-assembly-vote', 'mod-assembly', 'mod-vote']

for modal_id in modals_to_fix:
    pattern = f'<div class="ov" id="{modal_id}">'
    matches = list(re.finditer(re.escape(pattern), content))
    
    if len(matches) > 1:
        last_start = matches[-1].start()
        close_pattern = '</div>\n</div>'
        close_match = content.find(close_pattern, last_start)
        if close_match != -1:
            close_end = close_match + len(close_pattern)
            content = content[:close_match] + content[close_end:]

with open('./syndikpro/templates/partials/modals.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("Duplicates removed")
