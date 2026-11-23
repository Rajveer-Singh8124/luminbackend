# Lumin Optics API

This Flask service is the backend boundary for the React storefront. It exposes product, favorites, cart, checkout, account order, and health route shapes under `/api`.

For local MongoDB, set `MONGODB_URI` and optionally `MONGODB_DB`, install `requirements.txt`, then run `python app.py`. When no MongoDB URI is supplied, the service uses a small in-memory preview store so the frontend can still be developed without external infrastructure.
