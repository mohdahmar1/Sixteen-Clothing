require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, seed } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET === 'change-me') {
  console.error('Set a strong JWT_SECRET in .env before starting.');
  process.exit(1);
}
seed();

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '50kb' }));
const origins = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
if (origins.length) app.use(cors({ origin: origins }));

// Rate limits: general, plus stricter on login, orders and contact form.
const limiter = (max, minutes = 15) =>
  rateLimit({ windowMs: minutes * 60 * 1000, max, standardHeaders: true, legacyHeaders: false });
app.use('/api', limiter(300));

// ---------- helpers ----------
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const isPhone = v => /^[+]?[0-9 -]{8,15}$/.test(v);
const isEmail = v => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v);
const CATS = ['Men', 'Women', 'Outerwear'];
const STATUSES = ['new', 'confirmed', 'shipped', 'delivered', 'cancelled'];

function adminOnly(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  try { req.admin = jwt.verify(token, JWT_SECRET); next(); }
  catch { bad(res, 'Please log in as admin.', 401); }
}

// ---------- public: products ----------
app.get('/api/products', (req, res) => {
  const { category } = req.query;
  const rows = CATS.includes(category)
    ? db.prepare('SELECT id,name,category,price,description,image,stock FROM products WHERE active=1 AND category=? ORDER BY id DESC').all(category)
    : db.prepare('SELECT id,name,category,price,description,image,stock FROM products WHERE active=1 ORDER BY id DESC').all();
  res.json(rows);
});

app.get('/api/products/:id', (req, res) => {
  const p = db.prepare('SELECT id,name,category,price,description,image,stock FROM products WHERE id=? AND active=1').get(req.params.id);
  p ? res.json(p) : bad(res, 'Product not found.', 404);
});

// ---------- public: place an order ----------
// Prices always come from the database, never from the browser.
const createOrder = db.transaction((c, items, method) => {
  let total = 0;
  const lines = items.map(it => {
    const p = db.prepare('SELECT id,name,price,stock FROM products WHERE id=? AND active=1').get(it.productId);
    if (!p) throw Object.assign(new Error('A product in your bag is no longer available.'), { status: 400 });
    if (p.stock < it.qty) throw Object.assign(new Error(`Only ${p.stock} left of ${p.name}.`), { status: 409 });
    db.prepare('UPDATE products SET stock = stock - ? WHERE id=?').run(it.qty, p.id);
    total += p.price * it.qty;
    return { p, qty: it.qty, size: it.size };
  });
  const orderId = db.prepare(
    'INSERT INTO orders (customer_name,phone,email,address,total,payment_method) VALUES (?,?,?,?,?,?)'
  ).run(c.name, c.phone, c.email, c.address, total, method).lastInsertRowid;
  const insItem = db.prepare('INSERT INTO order_items (order_id,product_id,name,price,qty,size) VALUES (?,?,?,?,?,?)');
  lines.forEach(l => insItem.run(orderId, l.p.id, l.p.name, l.p.price, l.qty, l.size));
  return { orderId, total };
});

app.post('/api/orders', limiter(20, 60), (req, res) => {
  const c = req.body.customer || {};
  const customer = {
    name: str(c.name, 100), phone: str(c.phone, 20),
    email: str(c.email, 120), address: str(c.address, 400),
  };
  if (!customer.name || !customer.address) return bad(res, 'Name and address are required.');
  if (!isPhone(customer.phone)) return bad(res, 'Enter a valid phone number.');
  if (customer.email && !isEmail(customer.email)) return bad(res, 'Enter a valid email address.');

  const raw = Array.isArray(req.body.items) ? req.body.items : [];
  if (!raw.length || raw.length > 30) return bad(res, 'Your bag is empty.');
  const items = raw.map(i => ({
    productId: Number(i.productId), qty: Number(i.qty), size: str(i.size, 10),
  }));
  if (items.some(i => !Number.isInteger(i.productId) || !Number.isInteger(i.qty) || i.qty < 1 || i.qty > 10))
    return bad(res, 'Invalid item in your bag.');

  const method = req.body.paymentMethod === 'online' ? 'online' : 'cod';
  const { orderId, total } = createOrder(customer, items, method);
  // For online payment: create a Razorpay order here with `total` and return its id to the browser.
  res.status(201).json({ orderId, total, status: 'new' });
});

// Track an order: needs the order number and the phone used at checkout.
app.get('/api/orders/:id', limiter(30), (req, res) => {
  const o = db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id);
  if (!o || o.phone.replace(/\D/g, '') !== String(req.query.phone || '').replace(/\D/g, ''))
    return bad(res, 'No order found for that number and phone.', 404);
  const items = db.prepare('SELECT name,price,qty,size FROM order_items WHERE order_id=?').all(o.id);
  res.json({ id: o.id, status: o.status, paymentStatus: o.payment_status, total: o.total, createdAt: o.created_at, items });
});

// ---------- public: contact form ----------
app.post('/api/contact', limiter(5, 60), (req, res) => {
  const name = str(req.body.name, 100), email = str(req.body.email, 120), message = str(req.body.message, 2000);
  if (!name || !isEmail(email) || message.length < 5) return bad(res, 'Fill in your name, a valid email and a message.');
  db.prepare('INSERT INTO messages (name,email,message) VALUES (?,?,?)').run(name, email, message);
  res.status(201).json({ ok: true });
});

// ---------- admin ----------
app.post('/api/admin/login', limiter(10), wrap(async (req, res) => {
  const a = db.prepare('SELECT * FROM admins WHERE email=?').get(str(req.body.email, 120).toLowerCase());
  const ok = a && await bcrypt.compare(String(req.body.password || ''), a.password_hash);
  if (!ok) return bad(res, 'Wrong email or password.', 401);
  res.json({ token: jwt.sign({ id: a.id, email: a.email }, JWT_SECRET, { expiresIn: '8h' }) });
}));

app.get('/api/admin/orders', adminOnly, (req, res) => {
  const { status } = req.query;
  const rows = STATUSES.includes(status)
    ? db.prepare('SELECT * FROM orders WHERE status=? ORDER BY id DESC LIMIT 200').all(status)
    : db.prepare('SELECT * FROM orders ORDER BY id DESC LIMIT 200').all();
  const items = db.prepare('SELECT name,price,qty,size FROM order_items WHERE order_id=?');
  res.json(rows.map(o => ({ ...o, items: items.all(o.id) })));
});

app.patch('/api/admin/orders/:id', adminOnly, (req, res) => {
  const { status, paymentStatus } = req.body;
  const o = db.prepare('SELECT * FROM orders WHERE id=?').get(req.params.id);
  if (!o) return bad(res, 'Order not found.', 404);
  const nextStatus = status ?? o.status, nextPay = paymentStatus ?? o.payment_status;
  if (!STATUSES.includes(nextStatus) || !['pending', 'paid', 'refunded'].includes(nextPay)) return bad(res, 'Invalid status.');
  db.transaction(() => {
    // Cancelling an order puts the stock back.
    if (nextStatus === 'cancelled' && o.status !== 'cancelled')
      db.prepare('SELECT product_id,qty FROM order_items WHERE order_id=?').all(o.id)
        .forEach(i => db.prepare('UPDATE products SET stock = stock + ? WHERE id=?').run(i.qty, i.product_id));
    db.prepare('UPDATE orders SET status=?, payment_status=? WHERE id=?').run(nextStatus, nextPay, o.id);
  })();
  res.json({ ok: true });
});

function readProduct(b) {
  const p = {
    name: str(b.name, 120), category: b.category, price: Number(b.price),
    description: str(b.description, 1000), image: str(b.image, 300), stock: Number(b.stock),
  };
  if (!p.name || !CATS.includes(p.category) || !Number.isInteger(p.price) || p.price < 1 || !Number.isInteger(p.stock) || p.stock < 0) return null;
  return p;
}

app.get('/api/admin/products', adminOnly, (req, res) =>
  res.json(db.prepare('SELECT * FROM products ORDER BY id DESC').all()));

app.post('/api/admin/products', adminOnly, (req, res) => {
  const p = readProduct(req.body);
  if (!p) return bad(res, 'Check name, category, price and stock.');
  const id = db.prepare('INSERT INTO products (name,category,price,description,image,stock) VALUES (@name,@category,@price,@description,@image,@stock)').run(p).lastInsertRowid;
  res.status(201).json({ id });
});

app.put('/api/admin/products/:id', adminOnly, (req, res) => {
  const p = readProduct(req.body);
  if (!p) return bad(res, 'Check name, category, price and stock.');
  const r = db.prepare('UPDATE products SET name=@name,category=@category,price=@price,description=@description,image=@image,stock=@stock WHERE id=@id').run({ ...p, id: req.params.id });
  r.changes ? res.json({ ok: true }) : bad(res, 'Product not found.', 404);
});

// Products are hidden, not deleted, so old orders keep working.
app.delete('/api/admin/products/:id', adminOnly, (req, res) => {
  const r = db.prepare('UPDATE products SET active=0 WHERE id=?').run(req.params.id);
  r.changes ? res.json({ ok: true }) : bad(res, 'Product not found.', 404);
});

app.get('/api/admin/messages', adminOnly, (req, res) =>
  res.json(db.prepare('SELECT * FROM messages ORDER BY id DESC LIMIT 200').all()));

// ---------- site + errors ----------
app.use(express.static(path.join(__dirname, 'public')));   // put index.html and logo.png in /public
app.use('/api', (req, res) => bad(res, 'Not found.', 404));
app.use((err, req, res, next) => {
  if (err.status) return bad(res, err.message, err.status);
  console.error(err);
  bad(res, 'Something went wrong. Please try again.', 500);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Sixteen backend running on http://localhost:${port}`));
