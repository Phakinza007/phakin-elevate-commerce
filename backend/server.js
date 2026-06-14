require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const SECRET = process.env.JWT_SECRET || 'elevate_secret';
app.use(cors());
app.use(express.json());

// Database setup
const db = new Database(path.join(__dirname, 'elevate.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT DEFAULT 'customer', created_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, slug TEXT UNIQUE NOT NULL);
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT, category_id INTEGER REFERENCES categories(id),
    name TEXT NOT NULL, description TEXT, price REAL NOT NULL, compare_price REAL,
    stock INTEGER DEFAULT 0, sku TEXT UNIQUE, image_url TEXT, is_featured INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER REFERENCES users(id),
    guest_email TEXT, total REAL NOT NULL, status TEXT DEFAULT 'pending'
      CHECK(status IN ('pending','paid','processing','shipped','delivered','cancelled')),
    shipping_address TEXT, created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES products(id), name TEXT NOT NULL, price REAL NOT NULL, quantity INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER REFERENCES products(id),
    user_id INTEGER REFERENCES users(id), rating INTEGER CHECK(rating BETWEEN 1 AND 5),
    comment TEXT, created_at TEXT DEFAULT (datetime('now'))
  );
`);

// Seed
if (!db.prepare("SELECT id FROM categories LIMIT 1").get()) {
  const hash = bcrypt.hashSync('admin1234', 10);
  db.prepare("INSERT OR IGNORE INTO users (name, email, password, role) VALUES (?, ?, ?, ?)").run('Admin', 'admin@elevate.io', hash, 'admin');

  ['Clothing', 'Footwear', 'Accessories', 'Outerwear'].forEach(name =>
    db.prepare("INSERT OR IGNORE INTO categories (name, slug) VALUES (?, ?)").run(name, name.toLowerCase().replace(' ', '-'))
  );
  const cats = {};
  db.prepare("SELECT * FROM categories").all().forEach(c => { cats[c.name] = c.id; });

  const p = db.prepare("INSERT INTO products (category_id, name, description, price, compare_price, stock, sku, is_featured) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
  p.run(cats['Clothing'], 'Premium Slim Tee', 'Supima cotton everyday tee', 49, 79, 120, 'CLT-001', 1);
  p.run(cats['Clothing'], 'Linen Overshirt', 'Breathable relaxed-fit linen', 89, 129, 45, 'CLT-002', 1);
  p.run(cats['Footwear'], 'Clean Low Sneaker', 'Minimalist leather sneaker', 189, 249, 60, 'FTW-001', 1);
  p.run(cats['Footwear'], 'Chelsea Boot', 'Genuine leather pull-on boot', 259, 329, 30, 'FTW-002', 0);
  p.run(cats['Accessories'], 'Canvas Tote', 'Heavy waxed canvas tote bag', 69, null, 200, 'ACC-001', 1);
  p.run(cats['Outerwear'], 'Wool Overcoat', 'Italian wool blend longline coat', 399, 549, 15, 'OUT-001', 1);
}

// Auth middleware
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
};
const adminOnly = (req, res, next) => {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
};

// AUTH
app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  try {
    const r = db.prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)").run(name, email, bcrypt.hashSync(password, 10));
    const token = jwt.sign({ id: r.lastInsertRowid, email, role: 'customer' }, SECRET, { expiresIn: '7d' });
    res.status(201).json({ token });
  } catch { res.status(409).json({ error: 'Email already in use' }); }
});
app.post('/api/auth/login', (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(req.body.email);
  if (!user || !bcrypt.compareSync(req.body.password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

// PRODUCTS
app.get('/api/products', (req, res) => {
  const { search, category, featured, page = 1, limit = 12 } = req.query;
  let where = 'WHERE 1=1';
  const params = [];
  if (search)   { where += ' AND (p.name LIKE ? OR p.description LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
  if (category) { where += ' AND c.slug = ?'; params.push(category); }
  if (featured === 'true') where += ' AND p.is_featured = 1';
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const products = db.prepare(`
    SELECT p.*, c.name as category_name, c.slug as category_slug,
      COALESCE(AVG(r.rating), 0) as avg_rating, COUNT(r.id) as review_count
    FROM products p LEFT JOIN categories c ON c.id = p.category_id
    LEFT JOIN reviews r ON r.product_id = p.id
    ${where} GROUP BY p.id ORDER BY p.created_at DESC LIMIT ? OFFSET ?
  `).all(...params, parseInt(limit), offset);
  const total = db.prepare(`SELECT COUNT(*) as c FROM products p LEFT JOIN categories c ON c.id = p.category_id ${where}`).get(...params).c;
  res.json({ products, total, page: parseInt(page) });
});

app.get('/api/products/:id', (req, res) => {
  const product = db.prepare('SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON c.id = p.category_id WHERE p.id = ?').get(req.params.id);
  if (!product) return res.status(404).json({ error: 'Product not found' });
  const reviews = db.prepare('SELECT r.*, u.name as user_name FROM reviews r JOIN users u ON u.id = r.user_id WHERE r.product_id = ? ORDER BY r.created_at DESC').all(req.params.id);
  res.json({ ...product, reviews });
});

app.post('/api/products', authMiddleware, adminOnly, (req, res) => {
  const { category_id, name, description, price, compare_price, stock, sku, is_featured } = req.body;
  if (!name || !price) return res.status(400).json({ error: 'name and price are required' });
  try {
    const r = db.prepare('INSERT INTO products (category_id, name, description, price, compare_price, stock, sku, is_featured) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(category_id || null, name, description || null, price, compare_price || null, stock || 0, sku || null, is_featured ? 1 : 0);
    res.status(201).json({ id: r.lastInsertRowid });
  } catch { res.status(409).json({ error: 'SKU already exists' }); }
});

// CATEGORIES
app.get('/api/categories', (req, res) => {
  const rows = db.prepare('SELECT c.*, COUNT(p.id) as product_count FROM categories c LEFT JOIN products p ON p.category_id = c.id GROUP BY c.id ORDER BY c.name').all();
  res.json(rows);
});

// ORDERS
app.post('/api/orders', (req, res) => {
  const { items, shipping_address, guest_email } = req.body;
  if (!items?.length) return res.status(400).json({ error: 'items are required' });

  const token = req.headers.authorization?.split(' ')[1];
  let userId = null;
  if (token) { try { userId = jwt.verify(token, SECRET).id; } catch {} }

  let total = 0;
  const enrichedItems = items.map(item => {
    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(item.product_id);
    if (!product) throw new Error(`Product ${item.product_id} not found`);
    total += product.price * item.quantity;
    return { ...item, name: product.name, price: product.price };
  });

  const orderId = db.prepare('INSERT INTO orders (user_id, guest_email, total, shipping_address) VALUES (?, ?, ?, ?)').run(userId, guest_email || null, total, shipping_address || null).lastInsertRowid;
  const insertItem = db.prepare('INSERT INTO order_items (order_id, product_id, name, price, quantity) VALUES (?, ?, ?, ?, ?)');
  enrichedItems.forEach(i => insertItem.run(orderId, i.product_id, i.name, i.price, i.quantity));

  res.status(201).json({ id: orderId, total });
});

app.get('/api/orders', authMiddleware, (req, res) => {
  const where = req.user.role === 'admin' ? '' : 'WHERE o.user_id = ?';
  const params = req.user.role === 'admin' ? [] : [req.user.id];
  const orders = db.prepare(`SELECT o.* FROM orders o ${where} ORDER BY o.created_at DESC`).all(...params);
  res.json(orders);
});

app.patch('/api/orders/:id/status', authMiddleware, adminOnly, (req, res) => {
  const valid = ['pending', 'paid', 'processing', 'shipped', 'delivered', 'cancelled'];
  if (!valid.includes(req.body.status)) return res.status(400).json({ error: 'Invalid status' });
  db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(req.body.status, req.params.id);
  res.json({ message: 'Order status updated' });
});

// REVIEWS
app.post('/api/products/:id/reviews', authMiddleware, (req, res) => {
  const { rating, comment } = req.body;
  if (!rating) return res.status(400).json({ error: 'rating is required' });
  db.prepare('INSERT INTO reviews (product_id, user_id, rating, comment) VALUES (?, ?, ?, ?)').run(req.params.id, req.user.id, rating, comment || null);
  res.status(201).json({ message: 'Review added' });
});

app.get('/api/health', (_, res) => res.json({ status: 'ok', project: 'Elevate Commerce' }));

const PORT = process.env.PORT || 3005;
app.listen(PORT, () => console.log(`Elevate Commerce API running on http://localhost:${PORT}`));
