
def add_neighbor_post():
    import json
    r = get_current_resident()
    data = request.get_json() or {}
    
    author = (data.get('author_name') or data.get('contact_name') or f"{r.first_name} {r.last_name}").strip()
    phone = (data.get('phone') or '').strip()
    title = (data.get('title') or '').strip()
    
    if not title:
        return jsonify({'error': 'العنوان مطلوب'}), 400
    if not phone:
        return jsonify({'error': 'الهاتف مطلوب'}), 400
    
    images = data.get('images', [])
    images_json = json.dumps(images) if isinstance(images, list) and images else None
    
    post = NeighborPost(
        residence_id=r.residence_id,
        resident_id=r.id,
        type=data.get('type', 'sale') or 'sale',
        title=title,
        description=data.get('description', '').strip(),
        phone=phone,
        city=data.get('city', '').strip(),
        contact_name=author,
        author_name=author,
        images=images_json,
        scope=data.get('scope', 'private') or 'private',
        is_active=True,
    )
    db.session.add(post)
    db.session.commit()
    return jsonify({'ok': True, 'id': post.id})

