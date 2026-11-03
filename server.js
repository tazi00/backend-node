// Halwaji Maharaja Kitchen — Node.js backend (Express + MongoDB + JWT + WS)
// Parity with the FastAPI backend: same routes, same JSON shape.

require("dotenv").config();
const http = require("http");
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { v4: uuid } = require("uuid");
const { MongoClient } = require("mongodb");
const { WebSocketServer } = require("ws");

// ---------- Config ----------
const MONGO_URL = process.env.MONGO_URL || "mongodb://localhost:27017";
const DB_NAME = process.env.DB_NAME || "halwaji_maharaja";
const JWT_SECRET = process.env.JWT_SECRET || "halwaji-maharaja-kitchen-secret-key-2026-dev";
const JWT_EXPIRE_DAYS = Number(process.env.JWT_EXPIRE_DAYS || 30);
const PORT = Number(process.env.PORT || 8001);

// ---------- App ----------
const app = express();
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: "50mb" }));

const router = express.Router();
app.use("/api", router);

const now = () => new Date().toISOString();

// ---------- DB ----------
let db;
const mongo = new MongoClient(MONGO_URL);
async function initDb() {
  await mongo.connect();
  db = mongo.db(DB_NAME);
  console.log(`[db] connected → ${DB_NAME}`);
}

// ---------- Helpers ----------
function hashPassword(pw) { return bcrypt.hashSync(pw, 10); }
function verifyPassword(pw, hash) { try { return bcrypt.compareSync(pw, hash); } catch { return false; } }
function makeToken(user) {
  return jwt.sign({ uid: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: `${JWT_EXPIRE_DAYS}d` });
}
function decodeToken(t) { try { return jwt.verify(t, JWT_SECRET); } catch { return null; } }
function normalizePhone(p) { return (p || "").replace(/\D/g, "").slice(-10); }
function stripPrivate(u) {
  if (!u) return null;
  const { _id, password_hash, ...rest } = u;
  return rest;
}
function clean(doc) { if (!doc) return null; const { _id, ...rest } = doc; return rest; }
function cleanList(rows) { return rows.map(clean); }
function ah(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }

async function currentUser(req, res, next) {
  const auth = req.header("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ detail: "Missing token" });
  const payload = decodeToken(token);
  if (!payload) return res.status(401).json({ detail: "Invalid or expired token" });
  const user = await db.collection("users").findOne({ id: payload.uid });
  if (!user) return res.status(401).json({ detail: "User not found" });
  req.user = stripPrivate(user);
  next();
}
function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ detail: "Admin only" });
  next();
}

// ---------- Auth ----------
router.post("/auth/register", ah(async (req, res) => {
  const { name, email, password, phone, address, pin } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ detail: "name, email, password required" });
  const existing = await db.collection("users").findOne({ email: String(email).toLowerCase() });
  if (existing) return res.status(400).json({ detail: "Email already registered" });
  const id = uuid();
  const user = {
    id, name, email: String(email).toLowerCase(),
    password_hash: hashPassword(password),
    phone: phone ? normalizePhone(phone) : null,
    address: address || null, pin: pin || null,
    role: "customer", provider: "password",
    created_at: now(),
  };
  await db.collection("users").insertOne({ ...user });
  res.json({ token: makeToken(user), user: stripPrivate(user) });
}));

router.post("/auth/login", ah(async (req, res) => {
  const { email, password } = req.body || {};
  const user = await db.collection("users").findOne({ email: String(email || "").toLowerCase() });
  if (!user || !verifyPassword(password || "", user.password_hash)) {
    return res.status(401).json({ detail: "Invalid email or password" });
  }
  res.json({ token: makeToken(user), user: stripPrivate(user) });
}));

router.post("/auth/login-phone", ah(async (req, res) => {
  const phone = normalizePhone(req.body?.phone);
  if (!phone) return res.status(400).json({ detail: "Invalid phone" });
  const user = await db.collection("users").findOne({ phone });
  if (!user || !verifyPassword(req.body?.password || "", user.password_hash)) {
    return res.status(401).json({ detail: "Invalid phone or password" });
  }
  res.json({ token: makeToken(user), user: stripPrivate(user) });
}));

router.post("/auth/phone/send-otp", ah(async (req, res) => {
  const phone = normalizePhone(req.body?.phone);
  if (phone.length < 10) return res.status(400).json({ detail: "Enter a valid 10-digit phone number" });
  const user = await db.collection("users").findOne({ phone });
  if (!user) return res.status(404).json({ detail: "No account found with this phone. Please sign up first." });
  const otp = String(Math.floor(Math.random() * 1_000_000)).padStart(6, "0");
  const expires = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  await db.collection("phone_otps").updateOne(
    { phone },
    { $set: { phone, otp, expires_at: expires, attempts: 0 } },
    { upsert: true },
  );
  // TODO: send `otp` via your SMS gateway (Twilio / MSG91 / Fast2SMS). For demo we return it.
  res.json({ ok: true, expires_in: 300, demo_otp: otp, message: "OTP sent (demo mode — shown here until SMS gateway is connected)" });
}));

router.post("/auth/phone/verify-otp", ah(async (req, res) => {
  const phone = normalizePhone(req.body?.phone);
  const rec = await db.collection("phone_otps").findOne({ phone });
  if (!rec) return res.status(400).json({ detail: "No OTP requested. Tap Send OTP first." });
  if ((rec.attempts || 0) >= 5) return res.status(429).json({ detail: "Too many attempts. Request a new OTP." });
  if (rec.expires_at < now()) return res.status(400).json({ detail: "OTP expired. Send a new one." });
  if (String(rec.otp) !== String(req.body?.otp || "").trim()) {
    await db.collection("phone_otps").updateOne({ phone }, { $inc: { attempts: 1 } });
    return res.status(401).json({ detail: "Incorrect OTP" });
  }
  const user = await db.collection("users").findOne({ phone });
  if (!user) return res.status(404).json({ detail: "Account not found" });
  await db.collection("phone_otps").deleteOne({ phone });
  res.json({ token: makeToken(user), user: stripPrivate(user) });
}));

router.get("/auth/me", currentUser, (req, res) => res.json(req.user));

router.put("/auth/me", currentUser, ah(async (req, res) => {
  const allowed = ["name", "phone", "address", "pin"];
  const update = {};
  for (const k of allowed) if (req.body?.[k] !== undefined && req.body[k] !== null) update[k] = req.body[k];
  if (Object.keys(update).length) await db.collection("users").updateOne({ id: req.user.id }, { $set: update });
  const fresh = await db.collection("users").findOne({ id: req.user.id });
  res.json(stripPrivate(fresh));
}));

// ---------- Address Book ----------
router.get("/auth/addresses", currentUser, ah(async (req, res) => {
  const rows = await db.collection("addresses").find({ user_id: req.user.id }).sort({ created_at: 1 }).toArray();
  res.json(cleanList(rows));
}));
router.post("/auth/addresses", currentUser, ah(async (req, res) => {
  const b = req.body || {};
  const existing = await db.collection("addresses").countDocuments({ user_id: req.user.id });
  const doc = {
    id: uuid(), user_id: req.user.id,
    label: b.label, recipient_name: b.recipient_name, phone: b.phone,
    address: b.address, pin: b.pin,
    lat: b.lat ?? null, lng: b.lng ?? null,
    is_default: !!b.is_default || existing === 0,
    created_at: now(),
  };
  if (doc.is_default) await db.collection("addresses").updateMany({ user_id: req.user.id }, { $set: { is_default: false } });
  await db.collection("addresses").insertOne({ ...doc });
  res.json(clean(doc));
}));
router.put("/auth/addresses/:aid", currentUser, ah(async (req, res) => {
  const { aid } = req.params;
  const existing = await db.collection("addresses").findOne({ id: aid, user_id: req.user.id });
  if (!existing) return res.status(404).json({ detail: "Not found" });
  const b = req.body || {};
  if (b.is_default) await db.collection("addresses").updateMany({ user_id: req.user.id }, { $set: { is_default: false } });
  await db.collection("addresses").updateOne({ id: aid }, { $set: {
    label: b.label, recipient_name: b.recipient_name, phone: b.phone,
    address: b.address, pin: b.pin,
    lat: b.lat ?? null, lng: b.lng ?? null,
    is_default: !!b.is_default,
  }});
  const fresh = await db.collection("addresses").findOne({ id: aid });
  res.json(clean(fresh));
}));
router.delete("/auth/addresses/:aid", currentUser, ah(async (req, res) => {
  await db.collection("addresses").deleteOne({ id: req.params.aid, user_id: req.user.id });
  res.json({ ok: true });
}));

// ---------- Categories ----------
router.get("/categories", ah(async (_req, res) => {
  const items = await db.collection("categories").find({}).sort({ sort: 1 }).toArray();
  res.json(cleanList(items));
}));
router.post("/categories", currentUser, requireAdmin, ah(async (req, res) => {
  const doc = { id: uuid(), name: req.body.name, image: req.body.image || null, sort: req.body.sort || 0, created_at: now() };
  await db.collection("categories").insertOne({ ...doc });
  res.json(clean(doc));
}));
router.put("/categories/:cid", currentUser, requireAdmin, ah(async (req, res) => {
  await db.collection("categories").updateOne({ id: req.params.cid }, { $set: { name: req.body.name, image: req.body.image || null, sort: req.body.sort || 0 } });
  const cat = await db.collection("categories").findOne({ id: req.params.cid });
  if (!cat) return res.status(404).json({ detail: "Not found" });
  res.json(clean(cat));
}));
router.delete("/categories/:cid", currentUser, requireAdmin, ah(async (req, res) => {
  await db.collection("categories").deleteOne({ id: req.params.cid });
  res.json({ ok: true });
}));

// ---------- Products ----------
router.get("/products", ah(async (req, res) => {
  const q = {};
  if (req.query.category_id) q.category_id = req.query.category_id;
  if (req.query.q) q.name = { $regex: req.query.q, $options: "i" };
  const items = await db.collection("products").find(q).toArray();
  res.json(cleanList(items));
}));
router.get("/products/:pid", ah(async (req, res) => {
  const p = await db.collection("products").findOne({ id: req.params.pid });
  if (!p) return res.status(404).json({ detail: "Not found" });
  res.json(clean(p));
}));
router.post("/products", currentUser, requireAdmin, ah(async (req, res) => {
  const b = req.body || {};
  const doc = {
    id: uuid(),
    name: b.name, description: b.description || "", price: Number(b.price) || 0,
    category_id: b.category_id, image: b.image || null,
    available: b.available !== false, is_veg: b.is_veg !== false, featured: !!b.featured,
    created_at: now(),
  };
  await db.collection("products").insertOne({ ...doc });
  res.json(clean(doc));
}));
router.put("/products/:pid", currentUser, requireAdmin, ah(async (req, res) => {
  const b = req.body || {};
  await db.collection("products").updateOne({ id: req.params.pid }, { $set: {
    name: b.name, description: b.description || "", price: Number(b.price) || 0,
    category_id: b.category_id, image: b.image || null,
    available: b.available !== false, is_veg: b.is_veg !== false, featured: !!b.featured,
  }});
  const p = await db.collection("products").findOne({ id: req.params.pid });
  if (!p) return res.status(404).json({ detail: "Not found" });
  res.json(clean(p));
}));
router.delete("/products/:pid", currentUser, requireAdmin, ah(async (req, res) => {
  await db.collection("products").deleteOne({ id: req.params.pid });
  res.json({ ok: true });
}));

// ---------- Reels ----------
router.get("/reels", ah(async (_req, res) => {
  const items = await db.collection("reels").find({}).sort({ created_at: -1 }).toArray();
  res.json(cleanList(items));
}));
router.post("/reels", currentUser, requireAdmin, ah(async (req, res) => {
  const b = req.body || {};
  const doc = { id: uuid(), title: b.title, video_url: b.video_url, thumbnail: b.thumbnail || null, product_id: b.product_id || null, description: b.description || "", likes: 0, created_at: now() };
  await db.collection("reels").insertOne({ ...doc });
  res.json(clean(doc));
}));
router.delete("/reels/:rid", currentUser, requireAdmin, ah(async (req, res) => {
  await db.collection("reels").deleteOne({ id: req.params.rid });
  res.json({ ok: true });
}));

// ---------- Offers ----------
router.get("/offers", ah(async (req, res) => {
  const q = {};
  if (req.query.active_only === "true") {
    const nowIso = now();
    q.active = true;
    q.$and = [
      { $or: [{ starts_at: null }, { starts_at: { $lte: nowIso } }] },
      { $or: [{ ends_at: null }, { ends_at: { $gte: nowIso } }] },
    ];
  }
  const items = await db.collection("offers").find(q).sort({ created_at: -1 }).toArray();
  res.json(cleanList(items));
}));
router.post("/offers", currentUser, requireAdmin, ah(async (req, res) => {
  const b = req.body || {};
  const doc = {
    id: uuid(), title: b.title, description: b.description || "", code: (b.code || "").toUpperCase(),
    discount_pct: Number(b.discount_pct) || 0, max_discount: Number(b.max_discount) || 0, min_order: Number(b.min_order) || 0,
    starts_at: b.starts_at || null, ends_at: b.ends_at || null,
    active: b.active !== false, banner_image: b.banner_image || null,
    created_at: now(),
  };
  await db.collection("offers").insertOne({ ...doc });
  res.json(clean(doc));
}));
router.put("/offers/:oid", currentUser, requireAdmin, ah(async (req, res) => {
  const b = req.body || {};
  await db.collection("offers").updateOne({ id: req.params.oid }, { $set: {
    title: b.title, description: b.description || "", code: (b.code || "").toUpperCase(),
    discount_pct: Number(b.discount_pct) || 0, max_discount: Number(b.max_discount) || 0, min_order: Number(b.min_order) || 0,
    starts_at: b.starts_at || null, ends_at: b.ends_at || null,
    active: b.active !== false, banner_image: b.banner_image || null,
  }});
  const o = await db.collection("offers").findOne({ id: req.params.oid });
  if (!o) return res.status(404).json({ detail: "Not found" });
  res.json(clean(o));
}));
router.delete("/offers/:oid", currentUser, requireAdmin, ah(async (req, res) => {
  await db.collection("offers").deleteOne({ id: req.params.oid });
  res.json({ ok: true });
}));

// ---------- Notifications ----------
router.get("/notifications", ah(async (_req, res) => {
  const items = await db.collection("notifications").find({}).sort({ created_at: -1 }).toArray();
  res.json(cleanList(items));
}));
router.post("/notifications", currentUser, requireAdmin, ah(async (req, res) => {
  const doc = { id: uuid(), title: req.body.title, body: req.body.body, image: req.body.image || null, created_at: now() };
  await db.collection("notifications").insertOne({ ...doc });
  res.json(clean(doc));
}));
router.delete("/notifications/:nid", currentUser, requireAdmin, ah(async (req, res) => {
  await db.collection("notifications").deleteOne({ id: req.params.nid });
  res.json({ ok: true });
}));

// ---------- Settings ----------
router.get("/settings", ah(async (_req, res) => {
  let s = await db.collection("settings").findOne({ id: "global" });
  if (!s) {
    s = { id: "global", tax_pct: 5, delivery_fee: 40, restaurant_lat: 22.5726, restaurant_lng: 88.3639 };
    await db.collection("settings").insertOne({ ...s });
  }
  res.json(clean(s));
}));
router.put("/settings", currentUser, requireAdmin, ah(async (req, res) => {
  const b = req.body || {};
  await db.collection("settings").updateOne({ id: "global" }, { $set: {
    tax_pct: Number(b.tax_pct) || 0,
    delivery_fee: Number(b.delivery_fee) || 0,
    restaurant_lat: Number(b.restaurant_lat) || 0,
    restaurant_lng: Number(b.restaurant_lng) || 0,
  }}, { upsert: true });
  const s = await db.collection("settings").findOne({ id: "global" });
  res.json(clean(s));
}));

// ---------- Orders ----------
async function calcOrder(items, promoCode) {
  const cart = [];
  let subtotal = 0;
  for (const it of items || []) {
    const p = await db.collection("products").findOne({ id: it.product_id });
    if (!p) throw Object.assign(new Error(`Product not found: ${it.product_id}`), { status: 400 });
    const line = p.price * it.qty;
    subtotal += line;
    cart.push({ product_id: p.id, name: p.name, price: p.price, image: p.image || null, qty: it.qty, line_total: line });
  }
  const s = (await db.collection("settings").findOne({ id: "global" })) || { tax_pct: 5, delivery_fee: 40 };
  const tax = +(subtotal * s.tax_pct / 100).toFixed(2);
  const delivery = subtotal > 0 ? s.delivery_fee : 0;
  let discount = 0, promo = null;
  if (promoCode) {
    const offer = await db.collection("offers").findOne({ code: String(promoCode).toUpperCase(), active: true });
    if (offer && subtotal >= (offer.min_order || 0)) {
      let d = subtotal * offer.discount_pct / 100;
      if (offer.max_discount) d = Math.min(d, offer.max_discount);
      discount = +d.toFixed(2);
      promo = offer.code;
    }
  }
  const total = +(subtotal + tax + delivery - discount).toFixed(2);
  return { items: cart, subtotal: +subtotal.toFixed(2), tax, delivery_fee: delivery, discount, promo_code: promo, total };
}

router.post("/orders", currentUser, ah(async (req, res) => {
  const b = req.body || {};
  const calc = await calcOrder(b.items || [], b.promo_code);
  const order = {
    id: uuid(),
    user_id: req.user.id, user_name: req.user.name, user_email: req.user.email,
    address: b.address, phone: b.phone, pin: b.pin,
    payment_method: b.payment_method || "cod",
    payment_status: b.payment_method === "online" ? "paid" : "pending",
    status: "placed",
    notes: b.notes || null,
    customer_lat: b.customer_lat ?? null, customer_lng: b.customer_lng ?? null,
    delivery_lat: null, delivery_lng: null, delivery_partner: null,
    created_at: now(), updated_at: now(),
    ...calc,
  };
  await db.collection("orders").insertOne({ ...order });
  res.json(clean(order));
}));

router.get("/orders/mine", currentUser, ah(async (req, res) => {
  const items = await db.collection("orders").find({ user_id: req.user.id }).sort({ created_at: -1 }).toArray();
  res.json(cleanList(items));
}));

router.get("/orders", currentUser, requireAdmin, ah(async (req, res) => {
  const q = {};
  if (req.query.status_filter) q.status = req.query.status_filter;
  const items = await db.collection("orders").find(q).sort({ created_at: -1 }).toArray();
  res.json(cleanList(items));
}));

router.get("/orders/:oid", currentUser, ah(async (req, res) => {
  const o = await db.collection("orders").findOne({ id: req.params.oid });
  if (!o) return res.status(404).json({ detail: "Not found" });
  if (req.user.role !== "admin" && o.user_id !== req.user.id) return res.status(403).json({ detail: "Forbidden" });
  res.json(clean(o));
}));

router.put("/orders/:oid/status", currentUser, requireAdmin, ah(async (req, res) => {
  await db.collection("orders").updateOne({ id: req.params.oid }, { $set: { status: req.body.status, updated_at: now() } });
  const o = await db.collection("orders").findOne({ id: req.params.oid });
  if (!o) return res.status(404).json({ detail: "Not found" });
  res.json(clean(o));
}));

router.put("/orders/:oid/location", currentUser, requireAdmin, ah(async (req, res) => {
  await db.collection("orders").updateOne({ id: req.params.oid }, { $set: {
    delivery_lat: Number(req.body.lat), delivery_lng: Number(req.body.lng), updated_at: now(),
  }});
  const o = await db.collection("orders").findOne({ id: req.params.oid });
  if (!o) return res.status(404).json({ detail: "Not found" });
  res.json(clean(o));
}));

// ---------- Admin analytics ----------
function dateRangeQuery(start, end) {
  if (!start && !end) return {};
  const q = {};
  if (start) q.$gte = start;
  if (end) q.$lt = `${end}T23:59:59.999999+00:00`;
  return { created_at: q };
}

router.get("/admin/customers", currentUser, requireAdmin, ah(async (req, res) => {
  const q = { role: "customer", ...dateRangeQuery(req.query.start, req.query.end) };
  const rows = await db.collection("users").find(q).sort({ created_at: -1 }).toArray();
  const out = [];
  for (const u of rows) {
    const uid = u.id;
    const [agg] = await db.collection("orders").aggregate([
      { $match: { user_id: uid } },
      { $group: {
          _id: null,
          orders: { $sum: 1 },
          spent: { $sum: "$total" },
          last: { $max: "$created_at" },
          first: { $min: "$created_at" },
          delivered: { $sum: { $cond: [{ $eq: ["$status", "delivered"] }, 1, 0] } },
          cancelled: { $sum: { $cond: [{ $eq: ["$status", "cancelled"] }, 1, 0] } },
      }},
    ]).toArray();
    const topItems = await db.collection("orders").aggregate([
      { $match: { user_id: uid } },
      { $unwind: "$items" },
      { $group: { _id: "$items.name", qty: { $sum: "$items.qty" } } },
      { $sort: { qty: -1 } },
      { $limit: 5 },
    ]).toArray();
    const c = stripPrivate(u);
    c.orders_count = agg?.orders || 0;
    c.delivered_count = agg?.delivered || 0;
    c.cancelled_count = agg?.cancelled || 0;
    c.total_spent = Math.round(((agg?.spent) || 0) * 100) / 100;
    c.first_order = agg?.first || null;
    c.last_order = agg?.last || null;
    c.frequent_buyer = (agg?.orders || 0) >= 3;
    c.top_items = topItems.map((t) => ({ name: t._id, qty: t.qty }));
    out.push(c);
  }
  res.json(out);
}));

router.get("/admin/orders/report", currentUser, requireAdmin, ah(async (req, res) => {
  const q = { ...dateRangeQuery(req.query.start, req.query.end) };
  if (req.query.status_filter) q.status = req.query.status_filter;
  const items = await db.collection("orders").find(q).sort({ created_at: -1 }).toArray();
  const totalRevenue = items.reduce((s, o) => s + (o.total || 0), 0);
  const deliveredRevenue = items.filter((o) => o.status === "delivered").reduce((s, o) => s + (o.total || 0), 0);
  const byDay = {};
  for (const o of items) {
    const day = String(o.created_at || "").slice(0, 10);
    if (!day) continue;
    byDay[day] = byDay[day] || { count: 0, revenue: 0, delivered: 0 };
    byDay[day].count += 1;
    byDay[day].revenue += o.total || 0;
    if (o.status === "delivered") byDay[day].delivered += o.total || 0;
  }
  const daily = Object.entries(byDay)
    .map(([date, v]) => ({ date, count: v.count, revenue: +v.revenue.toFixed(2), delivered_revenue: +v.delivered.toFixed(2) }))
    .sort((a, b) => (a.date < b.date ? 1 : -1));
  res.json({
    total_orders: items.length,
    total_revenue: +totalRevenue.toFixed(2),
    delivered_revenue: +deliveredRevenue.toFixed(2),
    daily,
    orders: cleanList(items),
  });
}));

router.get("/admin/stats", currentUser, requireAdmin, ah(async (req, res) => {
  const q = dateRangeQuery(req.query.start, req.query.end);
  const today = new Date().toISOString().slice(0, 10);
  const [total_orders, today_orders, placed, preparing, out, delivered, products, customers] = await Promise.all([
    db.collection("orders").countDocuments(q),
    db.collection("orders").countDocuments({ created_at: { $gte: today } }),
    db.collection("orders").countDocuments({ ...q, status: "placed" }),
    db.collection("orders").countDocuments({ ...q, status: "preparing" }),
    db.collection("orders").countDocuments({ ...q, status: "out_for_delivery" }),
    db.collection("orders").countDocuments({ ...q, status: "delivered" }),
    db.collection("products").countDocuments({}),
    db.collection("users").countDocuments({ role: "customer", ...dateRangeQuery(req.query.start, req.query.end) }),
  ]);
  const [agg] = await db.collection("orders").aggregate([
    { $match: { ...q, status: "delivered" } },
    { $group: { _id: null, revenue: { $sum: "$total" } } },
  ]).toArray();
  res.json({
    total_orders, today_orders, placed, preparing, out_for_delivery: out, delivered,
    customers, products, revenue: agg ? +agg.revenue.toFixed(2) : 0,
  });
}));

// ---------- Chat REST helpers ----------
router.get("/chat/rooms", currentUser, requireAdmin, ah(async (_req, res) => {
  const rows = await db.collection("chat_messages").aggregate([
    { $sort: { ts: -1 } },
    { $group: { _id: "$room_id", last_text: { $first: "$text" }, last_ts: { $first: "$ts" }, sender_email: { $first: "$sender_email" } } },
    { $sort: { last_ts: -1 } },
    { $limit: 200 },
  ]).toArray();
  res.json(rows.map((r) => ({ room_id: r._id, last_text: r.last_text, last_ts: r.last_ts, sender_email: r.sender_email })));
}));

router.get("/chat/:roomId/messages", currentUser, ah(async (req, res) => {
  if (req.user.role !== "admin" && req.params.roomId !== `user_${req.user.id}`) return res.status(403).json({ detail: "Forbidden" });
  const msgs = await db.collection("chat_messages").find({ room_id: req.params.roomId }).sort({ ts: 1 }).toArray();
  res.json(cleanList(msgs));
}));

// ---------- Seed ----------
async function seed() {
  if ((await db.collection("users").countDocuments({ role: "admin" })) === 0) {
    await db.collection("users").insertOne({
      id: uuid(), name: "Maharaja Admin", email: "admin@halwaji.com",
      password_hash: hashPassword("admin123"), role: "admin", provider: "password",
      phone: "9999999999", address: "Maharaja Kitchen HQ, Kolkata", pin: "700001",
      created_at: now(),
    });
  }
  if ((await db.collection("settings").countDocuments({})) === 0) {
    await db.collection("settings").insertOne({ id: "global", tax_pct: 5, delivery_fee: 40, restaurant_lat: 22.5726, restaurant_lng: 88.3639 });
  }
  if ((await db.collection("categories").countDocuments({})) === 0) {
    const cats = [
      { name: "Bengali Sweets", image: "https://images.pexels.com/photos/8887052/pexels-photo-8887052.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", sort: 1 },
      { name: "Fish Curry", image: "https://images.pexels.com/photos/2474661/pexels-photo-2474661.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", sort: 2 },
      { name: "Biryani & Rice", image: "https://images.pexels.com/photos/9738983/pexels-photo-9738983.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", sort: 3 },
      { name: "Veg Specials", image: "https://images.pexels.com/photos/33643313/pexels-photo-33643313.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", sort: 4 },
      { name: "Snacks", image: "https://images.pexels.com/photos/37219215/pexels-photo-37219215.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", sort: 5 },
      { name: "Tandoor & Kebabs", image: "https://images.pexels.com/photos/2474661/pexels-photo-2474661.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", sort: 6 },
    ];
    const catIds = {};
    for (const c of cats) { const id = uuid(); await db.collection("categories").insertOne({ id, ...c, created_at: now() }); catIds[c.name] = id; }
    const imgChicken = "https://images.pexels.com/photos/2233348/pexels-photo-2233348.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940";
    const imgMutton = "https://images.pexels.com/photos/5950813/pexels-photo-5950813.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940";
    const imgFish = "https://images.pexels.com/photos/2474661/pexels-photo-2474661.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940";
    const imgEgg = "https://images.pexels.com/photos/6294287/pexels-photo-6294287.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940";
    const imgBiryani = "https://images.pexels.com/photos/9738983/pexels-photo-9738983.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940";
    const products = [
      { name: "Rasgulla (6 pcs)", description: "Soft, spongy Bengal classic in light sugar syrup.", price: 180, cat: "Bengali Sweets", image: "https://images.pexels.com/photos/8887052/pexels-photo-8887052.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", is_veg: true, featured: true },
      { name: "Mishti Doi", description: "Caramelised sweet yogurt in earthen pot.", price: 90, cat: "Bengali Sweets", image: "https://images.pexels.com/photos/37219215/pexels-photo-37219215.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", is_veg: true },
      { name: "Sandesh Platter", description: "Assorted Bengali sandesh, made fresh.", price: 220, cat: "Bengali Sweets", image: "https://images.pexels.com/photos/8887052/pexels-photo-8887052.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", is_veg: true },
      { name: "Aloo Posto", description: "Potato cooked with poppy seed paste.", price: 180, cat: "Veg Specials", image: "https://images.pexels.com/photos/33643313/pexels-photo-33643313.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", is_veg: true },
      { name: "Shukto", description: "Mixed vegetable mild curry.", price: 160, cat: "Veg Specials", image: "https://images.pexels.com/photos/33643313/pexels-photo-33643313.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", is_veg: true },
      { name: "Phuchka (12 pcs)", description: "Spicy tangy Kolkata street snack.", price: 80, cat: "Snacks", image: "https://images.pexels.com/photos/37219215/pexels-photo-37219215.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", is_veg: true, featured: true },
      { name: "Macher Jhol", description: "Traditional Bengali fish curry with potatoes.", price: 320, cat: "Fish Curry", image: imgFish, is_veg: false, featured: true },
      { name: "Chingri Malai Curry", description: "Prawns in coconut milk gravy.", price: 480, cat: "Fish Curry", image: imgFish, is_veg: false, featured: true },
      { name: "Ilish Bhapa", description: "Steamed Hilsa in mustard paste, queen of Bengal fish.", price: 520, cat: "Fish Curry", image: imgFish, is_veg: false, featured: true },
      { name: "Doi Maach", description: "Rohu fish in yogurt gravy with cumin and turmeric.", price: 360, cat: "Fish Curry", image: imgFish, is_veg: false },
      { name: "Sorshe Ilish", description: "Hilsa in pungent mustard sauce, slow-cooked.", price: 540, cat: "Fish Curry", image: imgFish, is_veg: false, featured: true },
      { name: "Kosha Mangsho", description: "Slow-cooked spicy Bengali mutton curry.", price: 460, cat: "Fish Curry", image: imgMutton, is_veg: false, featured: true },
      { name: "Kolkata Mutton Biryani", description: "Aromatic basmati with tender mutton, potato & egg.", price: 380, cat: "Biryani & Rice", image: imgBiryani, is_veg: false, featured: true },
      { name: "Chicken Biryani", description: "Fragrant rice with chicken, slow-cooked.", price: 280, cat: "Biryani & Rice", image: imgBiryani, is_veg: false },
      { name: "Egg Biryani", description: "Fragrant basmati layered with spiced boiled egg.", price: 220, cat: "Biryani & Rice", image: imgEgg, is_veg: false },
      { name: "Prawn Biryani", description: "Royal prawn biryani with kewra & saffron.", price: 420, cat: "Biryani & Rice", image: imgBiryani, is_veg: false, featured: true },
      { name: "Tandoori Chicken (Half)", description: "Charcoal-grilled chicken marinated overnight.", price: 260, cat: "Tandoor & Kebabs", image: imgChicken, is_veg: false, featured: true },
      { name: "Tandoori Chicken (Full)", description: "Whole tandoori chicken, slow-grilled in clay oven.", price: 480, cat: "Tandoor & Kebabs", image: imgChicken, is_veg: false, featured: true },
      { name: "Chicken Tikka", description: "Boneless chicken cubes marinated and grilled.", price: 280, cat: "Tandoor & Kebabs", image: imgChicken, is_veg: false, featured: true },
      { name: "Reshmi Kebab", description: "Silky chicken kebab in cashew-cream marinade.", price: 320, cat: "Tandoor & Kebabs", image: imgChicken, is_veg: false, featured: true },
      { name: "Mutton Seekh Kebab", description: "Spiced minced mutton skewers grilled to perfection.", price: 360, cat: "Tandoor & Kebabs", image: imgMutton, is_veg: false, featured: true },
      { name: "Mutton Galouti Kebab", description: "Melt-in-mouth Lucknowi minced mutton kebabs.", price: 380, cat: "Tandoor & Kebabs", image: imgMutton, is_veg: false },
      { name: "Tandoori Pomfret", description: "Whole pomfret marinated and char-grilled.", price: 480, cat: "Tandoor & Kebabs", image: imgFish, is_veg: false },
      { name: "Chicken Cutlet", description: "Crisp Kolkata-style chicken cutlet with kasundi.", price: 160, cat: "Snacks", image: imgChicken, is_veg: false },
      { name: "Mutton Chop", description: "Bengali mutton cutlet, crisp outside, juicy inside.", price: 180, cat: "Snacks", image: imgMutton, is_veg: false },
      { name: "Egg Roll", description: "Famous Kolkata street-style egg & onion paratha roll.", price: 90, cat: "Snacks", image: imgEgg, is_veg: false },
      { name: "Chicken Kathi Roll", description: "Spiced chicken wrapped in flaky paratha.", price: 130, cat: "Snacks", image: imgChicken, is_veg: false, featured: true },
    ];
    for (const p of products) {
      await db.collection("products").insertOne({
        id: uuid(), name: p.name, description: p.description, price: p.price,
        category_id: catIds[p.cat], image: p.image,
        available: true, is_veg: !!p.is_veg, featured: !!p.featured,
        created_at: now(),
      });
    }
  }
  if ((await db.collection("offers").countDocuments({})) === 0) {
    const offers = [
      { title: "Welcome Bengali Feast", description: "Get 15% off up to ₹100 on orders above ₹150.", code: "BENGAL15", discount_pct: 15, max_discount: 100, min_order: 150, active: true, banner_image: "https://images.pexels.com/photos/9738983/pexels-photo-9738983.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940" },
      { title: "Happy Hours", description: "Flat 20% off on Biryani between 3PM - 6PM.", code: "HAPPY20", discount_pct: 20, max_discount: 150, min_order: 200, active: true, banner_image: "https://images.pexels.com/photos/2474661/pexels-photo-2474661.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940" },
      { title: "Sweet Saturday", description: "10% off on all Bengali sweets.", code: "SWEET10", discount_pct: 10, max_discount: 80, min_order: 100, active: true, banner_image: "https://images.pexels.com/photos/8887052/pexels-photo-8887052.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940" },
    ];
    for (const o of offers) await db.collection("offers").insertOne({ id: uuid(), ...o, starts_at: null, ends_at: null, created_at: now() });
  }
  if ((await db.collection("notifications").countDocuments({})) === 0) {
    await db.collection("notifications").insertMany([
      { id: uuid(), title: "🎉 Welcome to Maharaja Kitchen!", body: "Use code BENGAL15 for 15% off your first order.", image: null, created_at: now() },
      { id: uuid(), title: "🍛 Happy Hours Live", body: "Flat 20% off on Biryani between 3PM - 6PM today.", image: null, created_at: now() },
    ]);
  }
  if ((await db.collection("reels").countDocuments({})) === 0) {
    const reels = [
      { title: "Sizzling Kolkata Biryani", video_url: "https://videos.pexels.com/video-files/3296009/3296009-uhd_2560_1440_30fps.mp4", thumbnail: "https://images.pexels.com/photos/9738983/pexels-photo-9738983.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", description: "Watch our Maharaja chefs craft the legendary Kolkata biryani." },
      { title: "Rasgulla Magic", video_url: "https://videos.pexels.com/video-files/4252087/4252087-uhd_2560_1440_25fps.mp4", thumbnail: "https://images.pexels.com/photos/8887052/pexels-photo-8887052.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", description: "The bouncy, syrup-soaked pride of Bengal." },
      { title: "Fish Curry Heritage", video_url: "https://videos.pexels.com/video-files/3296010/3296010-uhd_2560_1440_30fps.mp4", thumbnail: "https://images.pexels.com/photos/2474661/pexels-photo-2474661.jpeg?auto=compress&cs=tinysrgb&dpr=2&h=650&w=940", description: "Macher jhol straight from the Bengali kitchen." },
    ];
    for (const r of reels) await db.collection("reels").insertOne({ id: uuid(), ...r, product_id: null, likes: 0, created_at: now() });
  }
  return { ok: true, admin_login: { email: "admin@halwaji.com", password: "admin123" } };
}

router.post("/admin/seed", ah(async (_req, res) => res.json(await seed())));

router.get("/", (_req, res) => res.json({ app: "Halwaji Maharaja Kitchen", tagline: "Where Every Bite is the Taste of Bengal" }));

// ---------- Error handler ----------
app.use((err, _req, res, _next) => {
  console.error("[err]", err);
  res.status(err.status || 500).json({ detail: err.message || "Internal error" });
});

// ---------- WebSocket chat ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });
const rooms = new Map();
function joinRoom(roomId, ws) { if (!rooms.has(roomId)) rooms.set(roomId, new Set()); rooms.get(roomId).add(ws); }
function leaveRoom(roomId, ws) { rooms.get(roomId)?.delete(ws); }
function broadcast(roomId, message) {
  for (const ws of rooms.get(roomId) || []) { try { ws.send(JSON.stringify(message)); } catch {} }
}

server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url, "http://x");
  const m = url.pathname.match(/^\/api\/ws\/chat\/([^/]+)$/);
  if (!m) return socket.destroy();
  const token = url.searchParams.get("token");
  const payload = token ? decodeToken(token) : null;
  if (!payload) { socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n"); return socket.destroy(); }
  const roomId = decodeURIComponent(m[1]);
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws._roomId = roomId; ws._user = payload;
    wss.emit("connection", ws, req);
  });
});

wss.on("connection", async (ws) => {
  const roomId = ws._roomId; const payload = ws._user;
  joinRoom(roomId, ws);
  try {
    const history = await db.collection("chat_messages").find({ room_id: roomId }).sort({ ts: 1 }).toArray();
    for (const m of history) ws.send(JSON.stringify(clean(m)));
  } catch {}
  ws.on("message", async (raw) => {
    let data;
    try { data = JSON.parse(raw.toString()); } catch { return; }
    const text = String(data?.text || "").trim();
    if (!text) return;
    const msg = {
      id: uuid(), room_id: roomId,
      sender_id: payload.uid, sender_email: payload.email, sender_role: payload.role,
      text, ts: now(),
    };
    try { await db.collection("chat_messages").insertOne({ ...msg }); } catch {}
    broadcast(roomId, msg);
  });
  ws.on("close", () => leaveRoom(roomId, ws));
});

// ---------- Boot ----------
(async () => {
  await initDb();
  try { await seed(); } catch (e) { console.warn("[seed] failed:", e.message); }
  server.listen(PORT, "0.0.0.0", () => {
    console.log(`\n🍛 Halwaji Maharaja Kitchen — Node backend\n   HTTP  http://localhost:${PORT}/api\n   WS    ws://localhost:${PORT}/api/ws/chat/:roomId?token=<JWT>\n   Admin admin@halwaji.com / admin123\n`);
  });
})().catch((e) => { console.error("Boot failed:", e); process.exit(1); });
