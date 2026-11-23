import os
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

# Resolve from this file so `python backend/app.py` and running inside backend/
# both load the same project-root .env file.
load_dotenv(Path(__file__).resolve().parents[1] / '.env')

from flask import Flask, g, jsonify, request, send_from_directory
from flask_cors import CORS

from auth import (
    authenticate_admin,
    clean_product,
    clean_scalar,
    create_token,
    hash_password,
    normalize_email,
    require_admin,
    require_customer,
    validate_password,
    validate_safe_json,
    verify_password,
)
from db import store


app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# --- React build directory ---
# Adjust this if your build output lives somewhere else (e.g. ../frontend/build)
BUILD_DIR = (Path(__file__).resolve().parents[1] / 'frontend' / 'build').resolve()
# If the built index.html isn't there, we'll skip the SPA fallback gracefully.
SPA_INDEX = BUILD_DIR / 'index.html'


def account_public(user):
    return {'id': user['id'], 'name': user['name'], 'email': user['email']}


def account_payload(payload, require_name=False):
    if not isinstance(payload, dict):
        raise ValueError('Request body must be an object')
    allowed = {'name', 'email', 'password'}
    if set(payload) - allowed:
        raise ValueError('Unsupported account fields')
    name = clean_scalar(payload.get('name'), 'name', 100) if require_name else ''
    email = normalize_email(payload.get('email'))
    password = validate_password(payload.get('password'))
    return name, email, password


@app.get('/api/health')
def health():
    return jsonify({'status': 'ok', 'service': 'lumin-optics-api', 'database': store.status})


@app.get('/api/products')
def products():
    return jsonify({'products': store.list_products()})


@app.get('/api/products/<product_id>')
def product(product_id):
    item = store.get_product(product_id)
    if not item:
        return jsonify({'error': 'Product not found'}), 404
    return jsonify({'product': item})


@app.post('/api/auth/login')
def login():
    payload = request.get_json(silent=True) or {}
    try:
        validate_safe_json(payload)
    except ValueError as error:
        return jsonify({'error': str(error)}), 400
    email = payload.get('email')
    password = payload.get('password')
    if not isinstance(email, str) or not isinstance(password, str) or len(email) > 254 or len(password) > 256:
        return jsonify({'error': 'Invalid credentials'}), 401
    try:
        valid = authenticate_admin(email, password)
    except RuntimeError:
        return jsonify({'error': 'Admin authentication is not configured'}), 503
    if not valid:
        return jsonify({'error': 'Invalid credentials'}), 401
    email = email.strip().lower()
    return jsonify({'token': create_token(email, 'admin'), 'admin': {'email': email, 'role': 'admin'}})


@app.post('/api/auth/signup')
def signup():
    payload = request.get_json(silent=True) or {}
    try:
        validate_safe_json(payload)
        name, email, password = account_payload(payload, require_name=True)
    except ValueError as error:
        return jsonify({'error': str(error)}), 400
    user = {
        'id': f"usr_{uuid_token()}",
        'name': name,
        'email': email,
        'passwordHash': hash_password(password),
        'createdAt': datetime.now(timezone.utc).isoformat(),
    }
    public_user = store.create_user(user)
    if public_user is None:
        return jsonify({'error': 'An account with that email already exists'}), 409
    return jsonify({'token': create_token(email, 'customer'), 'user': {**account_public(public_user), 'role': 'customer'}}), 201


@app.post('/api/auth/customer-login')
def customer_login():
    payload = request.get_json(silent=True) or {}
    try:
        validate_safe_json(payload)
        _, email, password = account_payload(payload)
    except ValueError as error:
        return jsonify({'error': str(error)}), 400
    user = store.get_user(email)
    if not user or not verify_password(user.get('passwordHash'), password):
        return jsonify({'error': 'Invalid email or password'}), 401
    return jsonify({'token': create_token(email, 'customer'), 'user': {**account_public(user), 'role': 'customer'}})


@app.get('/api/account/session')
@require_customer
def account_session():
    user = store.get_user(g.customer_email)
    if not user:
        return jsonify({'error': 'Account not found'}), 401
    return jsonify({'user': {**account_public(user), 'role': 'customer'}})


@app.get('/api/admin/session')
@require_admin
def admin_session():
    return jsonify({'admin': {'email': getattr(g, 'admin_subject', ''), 'role': 'admin'}})


@app.put('/api/admin/products')
@require_admin
def replace_products():
    payload = request.get_json(silent=True) or {}
    try:
        validate_safe_json(payload)
    except ValueError as error:
        return jsonify({'error': str(error)}), 400
    products = payload.get('products')
    if not isinstance(products, list):
        return jsonify({'error': 'products must be an array'}), 400
    if len(products) > 500:
        return jsonify({'error': 'Too many products'}), 400
    try:
        clean_products = [clean_product(item) for item in products]
    except ValueError as error:
        return jsonify({'error': str(error)}), 400
    return jsonify({'products': store.replace_products(clean_products)})


@app.post('/api/favorites')
def favorites():
    payload = request.get_json(silent=True) or {}
    try:
        validate_safe_json(payload)
    except ValueError as error:
        return jsonify({'error': str(error)}), 400
    return jsonify(store.save_favorite(payload.get('productId'), payload.get('saved', True)))


@app.post('/api/cart')
def cart():
    payload = request.get_json(silent=True) or {}
    try:
        validate_safe_json(payload)
    except ValueError as error:
        return jsonify({'error': str(error)}), 400
    return jsonify(store.save_cart(payload))


@app.post('/api/checkout')
def checkout():
    payload = request.get_json(silent=True) or {}
    try:
        validate_safe_json(payload)
    except ValueError as error:
        return jsonify({'error': str(error)}), 400
    if not isinstance(payload, dict) or payload.keys() - {'customer', 'items', 'paymentMethod'}:
        return jsonify({'error': 'Unsupported checkout fields'}), 400
    if payload.get('paymentMethod') not in {'card', 'upi', 'cash_on_delivery'}:
        return jsonify({'error': 'Choose a supported payment method'}), 400
    order = store.create_order(payload)
    return jsonify(order), 201


@app.get('/api/account/orders')
def orders():
    return jsonify({'orders': store.list_orders()})


# --- SPA fallback: serve React build for any non-API route ---
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_spa(path):
    # Never swallow API routes
    if path.startswith('api/'):
        return jsonify({'error': 'Not found'}), 404

    # If the requested file exists in the build dir, serve it (js, css, images…)
    if path:
        candidate = BUILD_DIR / path
        if candidate.is_file():
            return send_from_directory(BUILD_DIR, path)

    # Otherwise fall back to index.html so React Router handles the route
    if SPA_INDEX.is_file():
        return send_from_directory(BUILD_DIR, 'index.html')

    return jsonify({'error': 'Frontend build not found. Expected index.html in ' + str(BUILD_DIR)}), 404


def uuid_token():
    # Kept local so the account ID never contains email or password data.
    from uuid import uuid4
    return uuid4().hex


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5001')), debug=os.getenv('FLASK_DEBUG') == '1')
