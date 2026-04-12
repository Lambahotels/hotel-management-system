const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// --- DATABASE SETUP ---
const DB_PATH = process.env.DB_PATH || './hotel_mgmt.db';
const db = new Database(DB_PATH);

function initDB() {
  db.exec(`PRAGMA journal_mode=WAL;`);

  db.exec(`
    CREATE TABLE IF NOT EXISTS hotels (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      code TEXT UNIQUE NOT NULL
    );

    CREATE TABLE IF NOT EXISTS rooms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hotel_id INTEGER NOT NULL,
      room_number TEXT NOT NULL,
      floor INTEGER NOT NULL,
      UNIQUE(hotel_id, room_number)
    );

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      hotel_id INTEGER,
      display_name TEXT
    );

    CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hotel_id INTEGER NOT NULL,
      room_id INTEGER NOT NULL,
      guest_name TEXT NOT NULL,
      guest_phone TEXT,
      booking_type TEXT NOT NULL,
      check_in TEXT NOT NULL,
      expected_checkout TEXT,
      actual_checkout TEXT,
      duration_label TEXT,
      amount REAL NOT NULL,
      payment_received REAL DEFAULT 0,
      status TEXT DEFAULT 'active',
      staff_id INTEGER NOT NULL,
      notes TEXT,
      created_at TEXT DEFAULT (datetime('now', 'localtime'))
    );

    CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      booking_id INTEGER NOT NULL,
      amount REAL NOT NULL,
      payment_mode TEXT DEFAULT 'Cash',
      staff_id INTEGER NOT NULL,
      notes TEXT,
      created_at TEXT DEFAULT (datetime('now', 'localtime'))
    );

    CREATE TABLE IF NOT EXISTS expenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hotel_id INTEGER NOT NULL,
      category TEXT NOT NULL,
      description TEXT,
      amount REAL NOT NULL,
      staff_id INTEGER NOT NULL,
      expense_date TEXT DEFAULT (date('now', 'localtime')),
      created_at TEXT DEFAULT (datetime('now', 'localtime'))
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      hotel_id INTEGER,
      action TEXT NOT NULL,
      details TEXT,
      created_at TEXT DEFAULT (datetime('now', 'localtime'))
    );
  `);

  // Seed hotels
  const ih = db.prepare('INSERT OR IGNORE INTO hotels (id, name, code) VALUES (?, ?, ?)');
  ih.run(1, 'Hotel Vardan', 'vardan');
  ih.run(2, 'OY Hotel', 'oy');
  ih.run(3, 'Royal Residency', 'rr');

  // Seed rooms
  const ir = db.prepare('INSERT OR IGNORE INTO rooms (hotel_id, room_number, floor) VALUES (?, ?, ?)');

  // Hotel 1 - Vardan: 101, 201, 301, 401
  [1, 2, 3, 4].forEach(f => ir.run(1, `${f}01`, f));

  // Hotel 2 - OY: 101,102,201,202,301,302,401,402
  [1, 2, 3, 4].forEach(f => {
    ir.run(2, `${f}01`, f);
    ir.run(2, `${f}02`, f);
  });

  // Hotel 3 - RR Residency: 101-105 ... 401-405
  [1, 2, 3, 4].forEach(f => {
    [1, 2, 3, 4, 5].forEach(r => ir.run(3, `${f}0${r}`, f));
  });

  // Seed users
  const iu = db.prepare('INSERT OR IGNORE INTO users (username, password, role, hotel_id, display_name) VALUES (?, ?, ?, ?, ?)');
  iu.run('owner',  bcrypt.hashSync('owner123',  10), 'owner', null, 'Owner');
  iu.run('vardan', bcrypt.hashSync('vardan123', 10), 'staff', 1,    'Vardan Staff');
  iu.run('oy',     bcrypt.hashSync('oy123',     10), 'staff', 2,    'OY Staff');
  iu.run('rr',     bcrypt.hashSync('rr123',     10), 'staff', 3,    'RR Staff');
}

initDB();

// --- MIDDLEWARE ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'hotel_secret_xK9mN2pQ',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 48 * 60 * 60 * 1000 }
}));

function auth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Please login first' });
  next();
}
function ownerOnly(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'owner') return res.status(403).json({ error: 'Owner access only' });
  next();
}
function log(userId, username, hotelId, action, details) {
  try { db.prepare('INSERT INTO audit_log (user_id, username, hotel_id, action, details) VALUES (?,?,?,?,?)').run(userId, username, hotelId, action, JSON.stringify(details)); } catch(e) {}
}
function canAccessHotel(user, hotelId) {
  if (user.role === 'owner') return true;
  return user.hotel_id === parseInt(hotelId);
}

// --- AUTH ---
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username?.trim());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Wrong username or password' });
  }
  req.session.user = { id: user.id, username: user.username, role: user.role, hotel_id: user.hotel_id, display_name: user.display_name };
  log(user.id, user.username, user.hotel_id, 'LOGIN', {});
  const hotel = user.hotel_id ? db.prepare('SELECT * FROM hotels WHERE id = ?').get(user.hotel_id) : null;
  res.json({ success: true, user: req.session.user, hotel });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.user) return res.json({ user: null });
  const hotel = req.session.user.hotel_id ? db.prepare('SELECT * FROM hotels WHERE id = ?').get(req.session.user.hotel_id) : null;
  res.json({ user: req.session.user, hotel });
});

app.post('/api/auth/change-password', auth, (req, res) => {
  const { current, newPass } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user.id);
  if (!bcrypt.compareSync(current, user.password)) return res.status(400).json({ error: 'Current password is wrong' });
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(bcrypt.hashSync(newPass, 10), user.id);
  res.json({ success: true });
});

// --- ROOMS ---
app.get('/api/rooms/:hotelId', auth, (req, res) => {
  const hotelId = parseInt(req.params.hotelId);
  if (!canAccessHotel(req.session.user, hotelId)) return res.status(403).json({ error: 'Access denied' });

  const rooms = db.prepare('SELECT * FROM rooms WHERE hotel_id = ? ORDER BY floor, room_number').all(hotelId);
  const active = db.prepare(`
    SELECT b.*, u.display_name as staff_name
    FROM bookings b JOIN users u ON b.staff_id = u.id
    WHERE b.hotel_id = ? AND b.status = 'active'
  `).all(hotelId);

  const map = {};
  active.forEach(b => { map[b.room_id] = b; });

  const now = new Date();
  res.json(rooms.map(r => {
    const booking = map[r.id] || null;
    let status = 'vacant';
    if (booking) {
      status = 'occupied';
      if (booking.expected_checkout && new Date(booking.expected_checkout) < now) status = 'overdue';
    }
    return { ...r, status, booking };
  }));
});

// --- BOOKINGS ---
app.post('/api/bookings', auth, (req, res) => {
  const { room_id, hotel_id, guest_name, guest_phone, booking_type, check_in, expected_checkout, duration_label, amount, notes } = req.body;

  if (!guest_name || !amount || !booking_type || !room_id) return res.status(400).json({ error: 'Please fill all required fields' });

  const existing = db.prepare(`SELECT id FROM bookings WHERE room_id = ? AND status = 'active'`).get(room_id);
  if (existing) return res.status(400).json({ error: 'Room is already occupied' });

  const checkIn = check_in || new Date().toLocaleString('en-IN', { hour12: false }).replace(',', '');
  const result = db.prepare(`
    INSERT INTO bookings (hotel_id, room_id, guest_name, guest_phone, booking_type, check_in, expected_checkout, duration_label, amount, staff_id, notes)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)
  `).run(parseInt(hotel_id), parseInt(room_id), guest_name.trim(), guest_phone || null, booking_type, checkIn, expected_checkout || null, duration_label || null, parseFloat(amount), req.session.user.id, notes || null);

  log(req.session.user.id, req.session.user.username, hotel_id, 'BOOKING_CREATED', { guest_name, room_id, amount });
  res.json({ success: true, booking_id: result.lastInsertRowid });
});

app.put('/api/bookings/:id/checkout', auth, (req, res) => {
  const id = parseInt(req.params.id);
  const b = db.prepare('SELECT * FROM bookings WHERE id = ?').get(id);
  if (!b) return res.status(404).json({ error: 'Booking not found' });
  if (b.status !== 'active') return res.status(400).json({ error: 'Already checked out' });

  const checkOut = new Date().toLocaleString('en-IN', { hour12: false }).replace(',', '');
  db.prepare(`UPDATE bookings SET status = 'checked_out', actual_checkout = ? WHERE id = ?`).run(checkOut, id);
  log(req.session.user.id, req.session.user.username, b.hotel_id, 'CHECKOUT', { booking_id: id, guest: b.guest_name });
  res.json({ success: true });
});

app.get('/api/bookings/:hotelId', auth, (req, res) => {
  const hotelId = parseInt(req.params.hotelId);
  if (!canAccessHotel(req.session.user, hotelId)) return res.status(403).json({ error: 'Access denied' });

  const { date, status } = req.query;
  let q = `SELECT b.*, r.room_number, r.floor, u.display_name as staff_name FROM bookings b JOIN rooms r ON b.room_id = r.id JOIN users u ON b.staff_id = u.id WHERE b.hotel_id = ?`;
  const params = [hotelId];
  if (date) { q += ` AND date(b.check_in) = ?`; params.push(date); }
  if (status) { q += ` AND b.status = ?`; params.push(status); }
  q += ` ORDER BY b.created_at DESC LIMIT 200`;
  res.json(db.prepare(q).all(...params));
});

// --- PAYMENTS ---
app.post('/api/payments', auth, (req, res) => {
  const { booking_id, amount, payment_mode, notes } = req.body;
  if (!booking_id || !amount) return res.status(400).json({ error: 'Missing fields' });

  const b = db.prepare('SELECT * FROM bookings WHERE id = ?').get(booking_id);
  if (!b) return res.status(404).json({ error: 'Booking not found' });

  db.prepare('INSERT INTO payments (booking_id, amount, payment_mode, staff_id, notes) VALUES (?,?,?,?,?)').run(parseInt(booking_id), parseFloat(amount), payment_mode || 'Cash', req.session.user.id, notes || null);
  db.prepare('UPDATE bookings SET payment_received = payment_received + ? WHERE id = ?').run(parseFloat(amount), parseInt(booking_id));

  log(req.session.user.id, req.session.user.username, b.hotel_id, 'PAYMENT_ADDED', { booking_id, amount, payment_mode });
  res.json({ success: true });
});

// --- EXPENSES ---
app.post('/api/expenses', auth, (req, res) => {
  const { hotel_id, category, description, amount, expense_date } = req.body;
  if (!hotel_id || !category || !amount) return res.status(400).json({ error: 'Missing fields' });
  if (!canAccessHotel(req.session.user, hotel_id)) return res.status(403).json({ error: 'Access denied' });

  db.prepare('INSERT INTO expenses (hotel_id, category, description, amount, staff_id, expense_date) VALUES (?,?,?,?,?,?)').run(parseInt(hotel_id), category, description || null, parseFloat(amount), req.session.user.id, expense_date || new Date().toISOString().substring(0, 10));
  log(req.session.user.id, req.session.user.username, hotel_id, 'EXPENSE_ADDED', { category, amount });
  res.json({ success: true });
});

app.get('/api/expenses/:hotelId', auth, (req, res) => {
  const hotelId = parseInt(req.params.hotelId);
  if (!canAccessHotel(req.session.user, hotelId)) return res.status(403).json({ error: 'Access denied' });
  const { date } = req.query;
  let q = `SELECT e.*, u.display_name as staff_name FROM expenses e JOIN users u ON e.staff_id = u.id WHERE e.hotel_id = ?`;
  const params = [hotelId];
  if (date) { q += ` AND e.expense_date = ?`; params.push(date); }
  q += ` ORDER BY e.created_at DESC`;
  res.json(db.prepare(q).all(...params));
});

// --- DASHBOARD (staff or single hotel) ---
app.get('/api/dashboard/:hotelId', auth, (req, res) => {
  const hotelId = parseInt(req.params.hotelId);
  if (!canAccessHotel(req.session.user, hotelId)) return res.status(403).json({ error: 'Access denied' });

  const today = new Date().toISOString().substring(0, 10);
  const hotel = db.prepare('SELECT * FROM hotels WHERE id = ?').get(hotelId);
  const totalRooms  = db.prepare('SELECT COUNT(*) as c FROM rooms WHERE hotel_id = ?').get(hotelId).c;
  const occupiedRooms = db.prepare(`SELECT COUNT(*) as c FROM bookings WHERE hotel_id = ? AND status = 'active'`).get(hotelId).c;
  const todayRevenue  = db.prepare(`SELECT COALESCE(SUM(p.amount),0) as t FROM payments p JOIN bookings b ON p.booking_id=b.id WHERE b.hotel_id=? AND date(p.created_at)=?`).get(hotelId, today).t;
  const todayBookings = db.prepare(`SELECT COUNT(*) as c FROM bookings WHERE hotel_id=? AND date(check_in)=?`).get(hotelId, today).c;
  const todayExpenses = db.prepare(`SELECT COALESCE(SUM(amount),0) as t FROM expenses WHERE hotel_id=? AND expense_date=?`).get(hotelId, today).t;
  const unpaid = db.prepare(`SELECT b.id, b.guest_name, r.room_number, b.amount, b.payment_received, b.check_in, b.booking_type FROM bookings b JOIN rooms r ON b.room_id=r.id WHERE b.hotel_id=? AND b.status='active' AND b.payment_received < b.amount`).all(hotelId);
  const overdue = db.prepare(`SELECT b.id, b.guest_name, r.room_number, b.expected_checkout FROM bookings b JOIN rooms r ON b.room_id=r.id WHERE b.hotel_id=? AND b.status='active' AND b.expected_checkout IS NOT NULL AND datetime(b.expected_checkout) < datetime('now','localtime')`).all(hotelId);

  res.json({ hotel, stats: { totalRooms, occupiedRooms, vacantRooms: totalRooms - occupiedRooms, todayRevenue, todayBookings, todayExpenses, netRevenue: todayRevenue - todayExpenses }, alerts: { unpaid, overdue } });
});

// --- OWNER DASHBOARD (all hotels) ---
app.get('/api/owner/dashboard', ownerOnly, (req, res) => {
  const today = new Date().toISOString().substring(0, 10);
  const hotels = db.prepare('SELECT * FROM hotels ORDER BY id').all();

  const hotelStats = hotels.map(hotel => {
    const totalRooms    = db.prepare('SELECT COUNT(*) as c FROM rooms WHERE hotel_id=?').get(hotel.id).c;
    const occupiedRooms = db.prepare(`SELECT COUNT(*) as c FROM bookings WHERE hotel_id=? AND status='active'`).get(hotel.id).c;
    const todayRevenue  = db.prepare(`SELECT COALESCE(SUM(p.amount),0) as t FROM payments p JOIN bookings b ON p.booking_id=b.id WHERE b.hotel_id=? AND date(p.created_at)=?`).get(hotel.id, today).t;
    const todayExpenses = db.prepare(`SELECT COALESCE(SUM(amount),0) as t FROM expenses WHERE hotel_id=? AND expense_date=?`).get(hotel.id, today).t;
    const unpaidCount   = db.prepare(`SELECT COUNT(*) as c FROM bookings WHERE hotel_id=? AND status='active' AND payment_received < amount`).get(hotel.id).c;
    const overdueCount  = db.prepare(`SELECT COUNT(*) as c FROM bookings b WHERE hotel_id=? AND status='active' AND expected_checkout IS NOT NULL AND datetime(expected_checkout) < datetime('now','localtime')`).get(hotel.id).c;
    const recentBookings = db.prepare(`SELECT b.guest_name, r.room_number, b.amount, b.payment_received, b.status, b.check_in, b.booking_type FROM bookings b JOIN rooms r ON b.room_id=r.id WHERE b.hotel_id=? ORDER BY b.created_at DESC LIMIT 5`).all(hotel.id);
    return { hotel, totalRooms, occupiedRooms, vacantRooms: totalRooms - occupiedRooms, todayRevenue, todayExpenses, netRevenue: todayRevenue - todayExpenses, unpaidCount, overdueCount, recentBookings };
  });

  const totals = { revenue: 0, expenses: 0, occupied: 0, total: 0 };
  hotelStats.forEach(h => { totals.revenue += h.todayRevenue; totals.expenses += h.todayExpenses; totals.occupied += h.occupiedRooms; totals.total += h.totalRooms; });
  totals.net = totals.revenue - totals.expenses;

  res.json({ date: today, hotels: hotelStats, totals });
});

// --- REPORTS ---
app.get('/api/reports/:hotelId', auth, (req, res) => {
  const hotelId = parseInt(req.params.hotelId);
  if (!canAccessHotel(req.session.user, hotelId)) return res.status(403).json({ error: 'Access denied' });

  const { from, to } = req.query;
  const fromDate = from || new Date().toISOString().substring(0, 10);
  const toDate   = to || fromDate;

  const bookings = db.prepare(`SELECT b.*, r.room_number, u.display_name as staff_name FROM bookings b JOIN rooms r ON b.room_id=r.id JOIN users u ON b.staff_id=u.id WHERE b.hotel_id=? AND date(b.check_in) BETWEEN ? AND ? ORDER BY b.check_in DESC`).all(hotelId, fromDate, toDate);
  const expenses = db.prepare(`SELECT e.*, u.display_name as staff_name FROM expenses e JOIN users u ON e.staff_id=u.id WHERE e.hotel_id=? AND e.expense_date BETWEEN ? AND ? ORDER BY e.expense_date DESC`).all(hotelId, fromDate, toDate);
  const totalRevenue  = db.prepare(`SELECT COALESCE(SUM(p.amount),0) as t FROM payments p JOIN bookings b ON p.booking_id=b.id WHERE b.hotel_id=? AND date(p.created_at) BETWEEN ? AND ?`).get(hotelId, fromDate, toDate).t;
  const totalExpenses = expenses.reduce((s, e) => s + e.amount, 0);

  res.json({ period: { from: fromDate, to: toDate }, bookings, expenses, summary: { totalBookings: bookings.length, totalRevenue, totalExpenses, netProfit: totalRevenue - totalExpenses } });
});

// --- AUDIT LOG ---
app.get('/api/audit', ownerOnly, (req, res) => {
  const { hotel_id } = req.query;
  let q = 'SELECT * FROM audit_log';
  const params = [];
  if (hotel_id) { q += ' WHERE hotel_id = ?'; params.push(parseInt(hotel_id)); }
  q += ' ORDER BY created_at DESC LIMIT 150';
  res.json(db.prepare(q).all(...params));
});

// Catch-all: serve frontend
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`Hotel Management System running on port ${PORT}`));
