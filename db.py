import os
from datetime import datetime, timezone
from uuid import uuid4

try:
    from pymongo import MongoClient
    from pymongo.errors import DuplicateKeyError
except ImportError:  # preview and lightweight local runs do not require MongoDB
    MongoClient = None
    DuplicateKeyError = None

PREVIEW_PRODUCTS = [
    {'id': 'cobalt-01', 'name': 'Cobalt 01', 'collection': 'Optical', 'price': 189},
    {'id': 'marlow-sun', 'name': 'Marlow Sun', 'collection': 'Sun', 'price': 215},
    {'id': 'orbit-clear', 'name': 'Orbit Clear', 'collection': 'Optical', 'price': 198},
]


class Store:
    def __init__(self):
        self.client = None
        self.db = None
        self.preview_products = list(PREVIEW_PRODUCTS)
        self.memory = {'favorites': set(), 'carts': {}, 'orders': [], 'users': {}}
        uri = os.getenv('MONGODB_URI')
        if MongoClient and uri:
            self.client = MongoClient(uri, serverSelectionTimeoutMS=1500)
            self.db = self.client[os.getenv('MONGODB_DB', 'lumin_optics')]
            self.db.users.create_index('email', unique=True)
            self.status = 'mongodb-ready'
        else:
            self.status = 'preview-memory'

    def list_products(self):
        if self.db is not None:
            return list(self.db.products.find({}, {'_id': 0}))
        return self.preview_products

    def get_product(self, product_id):
        if self.db is not None:
            return self.db.products.find_one({'id': product_id}, {'_id': 0})
        return next((item for item in self.preview_products if item['id'] == product_id), None)

    def replace_products(self, products):
        clean_products = [item for item in products if isinstance(item, dict) and item.get('id') and item.get('name')]
        if self.db is not None:
            self.db.products.delete_many({})
            if clean_products:
                self.db.products.insert_many(clean_products)
        else:
            self.preview_products = clean_products
        return self.list_products()

    def save_favorite(self, product_id, saved=True):
        if product_id:
            if saved:
                self.memory['favorites'].add(product_id)
            else:
                self.memory['favorites'].discard(product_id)
        return {'productId': product_id, 'saved': saved}

    def save_cart(self, payload):
        cart_id = payload.get('cartId', 'preview-cart')
        if self.db is not None:
            self.db.carts.update_one({'cartId': cart_id}, {'$set': {**payload, 'cartId': cart_id}}, upsert=True)
        else:
            self.memory['carts'][cart_id] = payload
        return {'cartId': cart_id, 'items': payload.get('items', [])}

    def create_order(self, payload):
        customer = payload.get('customer', {}) if isinstance(payload.get('customer', {}), dict) else {}
        customer = {key: value for key, value in customer.items() if key != 'card'}
        order = {
            'orderId': f"LO-{datetime.now(timezone.utc).strftime('%H%M%S%f')[-8:]}",
            'status': 'confirmed',
            'createdAt': datetime.now(timezone.utc).isoformat(),
            'customer': customer,
            'items': payload.get('items', []),
            'paymentMethod': payload.get('paymentMethod', 'card'),
        }
        if self.db is not None:
            self.db.orders.insert_one({**order})
        else:
            self.memory['orders'].append(order)
        return order

    def list_orders(self):
        if self.db is not None:
            return list(self.db.orders.find({}, {'_id': 0}).sort('createdAt', -1))
        return list(reversed(self.memory['orders']))

    def get_user(self, email):
        if self.db is not None:
            return self.db.users.find_one({'email': email}, {'_id': 0})
        return self.memory['users'].get(email)

    def create_user(self, user):
        if self.get_user(user['email']):
            return None
        if self.db is not None:
            try:
                self.db.users.insert_one(dict(user))
            except DuplicateKeyError:
                return None
        else:
            self.memory['users'][user['email']] = dict(user)
        return {key: value for key, value in user.items() if key != 'passwordHash'}


store = Store()
