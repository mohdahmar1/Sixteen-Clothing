const { DatabaseSync } = require('node:sqlite');   // built into Node 22.13+, nothing to compile
const bcrypt = require('bcryptjs');

const db = new DatabaseSync(process.env.DB_FILE || 'sixteen.db');
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');

// Runs a function as one all-or-nothing database transaction.
db.transaction = fn => (...args) => {
  db.exec('BEGIN');
  try { const r = fn(...args); db.exec('COMMIT'); return r; }
  catch (e) { db.exec('ROLLBACK'); throw e; }
};

db.exec(`
CREATE TABLE IF NOT EXISTS products (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT    NOT NULL,
  category    TEXT    NOT NULL CHECK (category IN ('Men','Women','Outerwear')),
  price       INTEGER NOT NULL CHECK (price > 0),          -- rupees
  description TEXT    NOT NULL DEFAULT '',
  image       TEXT    NOT NULL DEFAULT '',                 -- image URL or file name
  stock       INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
  active      INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS orders (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_name  TEXT NOT NULL,
  phone          TEXT NOT NULL,
  email          TEXT NOT NULL DEFAULT '',
  address        TEXT NOT NULL,
  total          INTEGER NOT NULL,
  status         TEXT NOT NULL DEFAULT 'new'
                 CHECK (status IN ('new','confirmed','shipped','delivered','cancelled')),
  payment_method TEXT NOT NULL DEFAULT 'cod' CHECK (payment_method IN ('cod','online')),
  payment_status TEXT NOT NULL DEFAULT 'pending' CHECK (payment_status IN ('pending','paid','refunded')),
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS order_items (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id   INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id INTEGER NOT NULL REFERENCES products(id),
  name       TEXT    NOT NULL,   -- copied at purchase time so old orders stay correct
  price      INTEGER NOT NULL,   -- price per unit at purchase time
  qty        INTEGER NOT NULL CHECK (qty > 0),
  size       TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS messages (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  email      TEXT NOT NULL,
  message    TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS admins (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_products_category ON products(category, active);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status, created_at);
`);

// First run: create the owner account and the sample catalogue.
function seed() {
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  if (email && password && !db.prepare('SELECT 1 FROM admins LIMIT 1').get()) {
    db.prepare('INSERT INTO admins (email, password_hash) VALUES (?, ?)')
      .run(email.toLowerCase(), bcrypt.hashSync(password, 12));
  }
  if (!db.prepare('SELECT 1 FROM products LIMIT 1').get()) {
    const ins = db.prepare('INSERT INTO products (name, category, price, stock) VALUES (?,?,?,?)');
    [
      ['Boxy Cotton Tee', 'Men', 1299, 40],
      ['Linen Camp Shirt', 'Men', 2199, 25],
      ['Tapered Trousers', 'Men', 2799, 20],
      ['Wool Overcoat', 'Outerwear', 8499, 8],
      ['Rib Knit Top', 'Women', 1799, 30],
      ['Wide-Leg Trousers', 'Women', 2999, 18],
      ['Relaxed Blazer', 'Outerwear', 5499, 10],
      ['Heavy Knit Pullover', 'Women', 3499, 15],
    ].forEach(p => ins.run(...p));
  }
}

module.exports = { db, seed };
