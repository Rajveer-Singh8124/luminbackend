import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from hmac import compare_digest

import jwt
from flask import g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash


ALLOWED_EMAIL_MAX = 254
PASSWORD_MAX = 128


def validate_safe_json(value, depth=0):
    """Reject Mongo-style operators and dotted paths before any persistence."""
    if depth > 8:
        raise ValueError('Request data is nested too deeply')
    if isinstance(value, dict):
        if len(value) > 80:
            raise ValueError('Request object has too many fields')
        for key, child in value.items():
            if not isinstance(key, str) or not key or key.startswith('$') or '.' in key or len(key) > 80:
                raise ValueError('Request contains an unsafe field name')
            validate_safe_json(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > 500:
            raise ValueError('Request list is too long')
        for child in value:
            validate_safe_json(child, depth + 1)
    elif isinstance(value, str) and (len(value) > 5000 or '\x00' in value):
        raise ValueError('Request contains invalid text')
    return value


def _secret():
    return os.getenv('JWT_SECRET', '')


def create_token(subject, role='admin'):
    secret = _secret()
    if not secret:
        raise RuntimeError('JWT_SECRET is not configured')
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {'sub': subject, 'role': role, 'iat': now, 'exp': now + timedelta(minutes=30)},
        secret,
        algorithm='HS256',
    )


def _require_role(role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            header = request.headers.get('Authorization', '')
            if not header.startswith('Bearer '):
                return jsonify({'error': 'Authentication required'}), 401
            try:
                claims = jwt.decode(header[7:].strip(), _secret(), algorithms=['HS256'])
                if claims.get('role') != role or not claims.get('sub'):
                    raise jwt.InvalidTokenError('wrong role')
                g.auth_subject = claims['sub']
                g.auth_role = role
                if role == 'admin':
                    g.admin_subject = claims['sub']
                if role == 'customer':
                    g.customer_email = claims['sub']
            except (jwt.PyJWTError, RuntimeError, TypeError):
                return jsonify({'error': 'Invalid or expired authentication token'}), 401
            return view(*args, **kwargs)
        return wrapped
    return decorator


def require_admin(view):
    return _require_role('admin')(view)


def require_customer(view):
    return _require_role('customer')(view)


def normalize_email(value):
    if not isinstance(value, str):
        raise ValueError('Email address is required')
    email = value.strip().lower()
    if len(email) > ALLOWED_EMAIL_MAX or '@' not in email or email.startswith('@') or email.endswith('@'):
        raise ValueError('Enter a valid email address')
    local, _, domain = email.rpartition('@')
    if not local or '.' not in domain or domain.startswith('.') or domain.endswith('.'):
        raise ValueError('Enter a valid email address')
    return email


def validate_password(value):
    if not isinstance(value, str) or len(value) < 8 or len(value) > PASSWORD_MAX:
        raise ValueError('Password must be 8–128 characters')
    if '\x00' in value:
        raise ValueError('Password contains an invalid character')
    return value


def hash_password(password):
    # Passwords are salted and one-way hashed; plaintext is never persisted.
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)


def verify_password(password_hash, password):
    try:
        return isinstance(password_hash, str) and check_password_hash(password_hash, password)
    except (TypeError, ValueError):
        return False


def authenticate_admin(email, password):
    configured_email = os.getenv('ADMIN_EMAIL', '')
    configured_password = os.getenv('ADMIN_PASSWORD', '')
    if not configured_email or not configured_password or not _secret():
        raise RuntimeError('Admin authentication is not configured')
    if not isinstance(email, str) or not isinstance(password, str):
        return False
    return compare_digest(email.strip().lower(), configured_email.strip().lower()) and compare_digest(password, configured_password)


def clean_scalar(value, field, max_length=500):
    if not isinstance(value, str):
        raise ValueError(f'{field} must be text')
    value = value.strip()
    if len(value) > max_length:
        raise ValueError(f'{field} is too long')
    if '\x00' in value:
        raise ValueError(f'{field} contains an invalid character')
    return value


def clean_product(raw):
    if not isinstance(raw, dict):
        raise ValueError('Each product must be an object')
    if any(not isinstance(key, str) or key.startswith('$') or '.' in key for key in raw):
        raise ValueError('Product contains an unsafe field name')
    allowed = {'id', 'name', 'collection', 'category', 'shape', 'price', 'oldPrice', 'badge', 'color', 'description', 'image', 'imageAlt', 'details'}
    if set(raw) - allowed:
        raise ValueError('Product contains an unsupported field')
    product = {
        'id': clean_scalar(raw.get('id'), 'id', 80),
        'name': clean_scalar(raw.get('name'), 'name', 120),
        'collection': clean_scalar(raw.get('collection'), 'collection', 60),
        'category': clean_scalar(raw.get('category'), 'category', 60),
        'shape': clean_scalar(raw.get('shape'), 'shape', 60),
        'badge': clean_scalar(raw.get('badge', 'New frame'), 'badge', 60),
        'color': clean_scalar(raw.get('color', ''), 'color', 100),
        'description': clean_scalar(raw.get('description', ''), 'description', 800),
        'image': clean_scalar(raw.get('image'), 'image', 1500),
        'imageAlt': clean_scalar(raw.get('imageAlt', ''), 'imageAlt', 240),
    }
    if not product['image'].startswith(('https://', 'http://', '/manus-storage/')):
        raise ValueError('image must use http(s) or project storage')
    price = raw.get('price')
    old_price = raw.get('oldPrice')
    if isinstance(price, bool) or not isinstance(price, (int, float)) or price <= 0 or price > 100000:
        raise ValueError('price must be a positive number')
    if old_price is not None and (isinstance(old_price, bool) or not isinstance(old_price, (int, float)) or old_price <= 0 or old_price > 100000):
        raise ValueError('oldPrice must be a positive number or null')
    details = raw.get('details', [])
    if not isinstance(details, list) or len(details) > 12:
        raise ValueError('details must be a short list')
    product['price'] = round(float(price), 2)
    product['oldPrice'] = round(float(old_price), 2) if old_price is not None else None
    product['details'] = [clean_scalar(item, 'detail', 160) for item in details]
    return product
