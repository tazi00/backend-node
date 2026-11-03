# Halwaji Maharaja Kitchen — Node.js Backend

Full parity with the FastAPI backend. Same routes, same JSON shape — your existing Expo mobile app + web admin panel work with zero frontend changes.

## Requirements
- **Node.js 18+**
- **MongoDB 5+** running locally (or an Atlas connection string)

## Quick start

```bash
cd backend-node
npm install
cp .env.example .env      # then edit MONGO_URL / JWT_SECRET / PORT
npm run dev               # auto-restart on save
# or
npm start
```

Server boots at **http://localhost:8001**. On first start it seeds:
- Admin: `admin@halwaji.com` / `admin123`
- 6 categories, 27 dishes (veg + non-veg), 3 offers, 2 notifications, 3 reels, default settings.

## Point your Expo frontend at the local backend

In `frontend/.env`:
```
EXPO_PUBLIC_BACKEND_URL=http://<YOUR_LAN_IP>:8001
```
(`localhost` for web preview on the same machine; on a real phone use your LAN IP e.g. `http://192.168.1.10:8001`).

## Endpoints (identical to Python backend)

Auth
- `POST /api/auth/register`
- `POST /api/auth/login` — email + password
- `POST /api/auth/login-phone` — phone + password
- `POST /api/auth/phone/send-otp` — returns `demo_otp` until SMS gateway is wired
- `POST /api/auth/phone/verify-otp`
- `GET/PUT /api/auth/me`
- `GET/POST/PUT/DELETE /api/auth/addresses[/:id]`

Catalog (public GETs, admin writes)
- `/api/categories`, `/api/products`, `/api/reels`, `/api/offers`, `/api/notifications`, `/api/settings`

Orders
- `POST /api/orders` · `GET /api/orders/mine` · `GET /api/orders` (admin) · `GET /api/orders/:id`
- `PUT /api/orders/:id/status` · `PUT /api/orders/:id/location`

Admin analytics
- `GET /api/admin/stats?start=YYYY-MM-DD&end=YYYY-MM-DD`
- `GET /api/admin/customers?start=&end=`
- `GET /api/admin/orders/report?start=&end=&status_filter=`

Chat
- `WS  /api/ws/chat/:roomId?token=<JWT>`
- `GET /api/chat/rooms` (admin) · `GET /api/chat/:roomId/messages`

Reseed anytime: `POST /api/admin/seed` (idempotent — only inserts when a collection is empty).

## Deploy anywhere
Render / Railway / Fly / EC2 / DigitalOcean — set env vars, run `npm install && npm start`. Point mobile app's `EXPO_PUBLIC_BACKEND_URL` at the public URL.

## Notes
- `bcryptjs` (pure JS) — no native build tools required.
- Native `mongodb` driver — same schema as the Python backend.
- WebSocket path: `/api/ws/chat/:roomId`, JWT via `?token=...` query param.
