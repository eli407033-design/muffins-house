from flask import Flask, request, redirect, url_for, session, flash, render_template_string, abort
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import sqlite3
import os
import secrets
import random
import urllib.parse

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['DATABASE'] = 'muffins.db'
app.config['DELIVERY_FEE'] = 0.0
app.config['OTP_EXPIRY_MINUTES'] = 5
app.config['BUSINESS_NAME'] = 'Muffin House'
app.config['BUSINESS_PHONE'] = '260973307154'
app.config['CURRENCY'] = 'ZMW'
app.config['LOGO_PATH'] = '/static/logo.png'

HOME_IMAGE_PATH = '/static/lemon_muffins.jpg'


# -----------------------------
# Database helpers
# -----------------------------
def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(conn, table_name, column_name):
    cols = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(col[1] == column_name for col in cols)


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            room_number TEXT,
            phone TEXT,
            phone_verified INTEGER NOT NULL DEFAULT 0,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS menu_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            category TEXT DEFAULT 'Classic',
            image_url TEXT DEFAULT '',
            is_available INTEGER NOT NULL DEFAULT 1,
            is_coming_soon INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            fulfillment_type TEXT NOT NULL,
            room_number TEXT,
            phone TEXT,
            special_instructions TEXT,
            unit_price REAL NOT NULL DEFAULT 0,
            delivery_fee REAL NOT NULL DEFAULT 0,
            total_price REAL NOT NULL,
            order_status TEXT NOT NULL DEFAULT 'Pending',
            payment_status TEXT NOT NULL DEFAULT 'Pending',
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(item_id) REFERENCES menu_items(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            phone TEXT NOT NULL,
            otp_code TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            is_used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    if not column_exists(conn, 'users', 'phone_verified'):
        cur.execute("ALTER TABLE users ADD COLUMN phone_verified INTEGER NOT NULL DEFAULT 0")
    if not column_exists(conn, 'menu_items', 'category'):
        cur.execute("ALTER TABLE menu_items ADD COLUMN category TEXT DEFAULT 'Classic'")
    if not column_exists(conn, 'menu_items', 'image_url'):
        cur.execute("ALTER TABLE menu_items ADD COLUMN image_url TEXT DEFAULT ''")
    if not column_exists(conn, 'menu_items', 'is_coming_soon'):
        cur.execute("ALTER TABLE menu_items ADD COLUMN is_coming_soon INTEGER NOT NULL DEFAULT 0")
    if not column_exists(conn, 'orders', 'unit_price'):
        cur.execute("ALTER TABLE orders ADD COLUMN unit_price REAL NOT NULL DEFAULT 0")
    if not column_exists(conn, 'orders', 'delivery_fee'):
        cur.execute("ALTER TABLE orders ADD COLUMN delivery_fee REAL NOT NULL DEFAULT 0")

    conn.commit()

    admin_exists = cur.execute("SELECT id FROM users WHERE username = ?", ('admin',)).fetchone()
    if not admin_exists:
        cur.execute('''
            INSERT INTO users (full_name, username, email, password_hash, room_number, phone, phone_verified, is_admin, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            'Business Admin',
            'admin',
            'admin@muffinbusiness.com',
            generate_password_hash('ChangeMe123!'),
            '',
            '',
            1,
            1,
            datetime.utcnow().isoformat()
        ))

    item_count = cur.execute("SELECT COUNT(*) AS count FROM menu_items").fetchone()['count']
    if item_count == 0:
        items = [
            (
                'Lemon Muffin',
                'Fresh homemade lemon-flavoured muffin. This is the only flavor currently available. Delivery is free within UNZA campus.',
                5.0,
                'Lemon',
                HOME_IMAGE_PATH,
                1,
                0,
                datetime.utcnow().isoformat()
            ),
            (
                'Chocolate Muffin',
                'Rich chocolate muffin. Coming soon.',
                18.0,
                'Chocolate',
                HOME_IMAGE_PATH,
                0,
                1,
                datetime.utcnow().isoformat()
            ),
            (
                'Vanilla Muffin',
                'Soft vanilla muffin. Coming soon.',
                16.0,
                'Vanilla',
                HOME_IMAGE_PATH,
                0,
                1,
                datetime.utcnow().isoformat()
            ),
            (
                'Blueberry Muffin',
                'Blueberry muffin. Coming soon.',
                20.0,
                'Fruit',
                HOME_IMAGE_PATH,
                0,
                1,
                datetime.utcnow().isoformat()
            ),
        ]
        cur.executemany('''
            INSERT INTO menu_items (name, description, price, category, image_url, is_available, is_coming_soon, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', items)

    conn.commit()
    conn.close()


@app.before_request
def ensure_db_ready():
    if not hasattr(app, '_db_initialized'):
        init_db()
        app._db_initialized = True


# -----------------------------
# Security helpers
# -----------------------------
def generate_csrf_token():
    token = secrets.token_urlsafe(32)
    session['_csrf_token'] = token
    return token


def validate_csrf():
    form_token = request.form.get('_csrf_token', '')
    session_token = session.get('_csrf_token', '')
    return form_token and session_token and secrets.compare_digest(form_token, session_token)


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': generate_csrf_token}


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapper


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            abort(403)
        return view_func(*args, **kwargs)
    return wrapper


def verified_phone_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        conn = get_db_connection()
        user = conn.execute('SELECT phone_verified FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        if not user or not user['phone_verified']:
            flash('Please verify your phone number with OTP before placing orders.', 'warning')
            return redirect(url_for('verify_phone'))
        return view_func(*args, **kwargs)
    return wrapper


def sanitize_text(value, max_len=255):
    value = (value or '').strip()
    return value[:max_len]


def calculate_totals(unit_price, quantity, fulfillment_type):
    subtotal = unit_price * quantity
    delivery_fee = app.config['DELIVERY_FEE'] if fulfillment_type == 'Delivery' else 0.0
    total = subtotal + delivery_fee
    return subtotal, delivery_fee, total


def generate_otp():
    return str(random.randint(100000, 999999))


def create_otp_for_user(user_id, phone):
    conn = get_db_connection()
    conn.execute('UPDATE otp_codes SET is_used = 1 WHERE user_id = ? AND is_used = 0', (user_id,))
    code = generate_otp()
    expires_at = (datetime.utcnow() + timedelta(minutes=app.config['OTP_EXPIRY_MINUTES'])).isoformat()
    conn.execute('''
        INSERT INTO otp_codes (user_id, phone, otp_code, expires_at, is_used, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, phone, code, expires_at, 0, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    print(f"[OTP DEBUG] Send this OTP to {phone}: {code}")
    return code


def build_whatsapp_url(message: str) -> str:
    encoded_message = urllib.parse.quote(message)
    return f"https://wa.me/{app.config['BUSINESS_PHONE']}?text={encoded_message}"


def build_order_whatsapp_message(item_name, quantity, fulfillment_type, room_number, phone, total_price):
    room_line = room_number if room_number else 'N/A'
    return (
        f"Hello {app.config['BUSINESS_NAME']}, I have placed an order.\n"
        f"Item: {item_name}\n"
        f"Quantity: {quantity}\n"
        f"Fulfillment: {fulfillment_type}\n"
        f"Room: {room_line}\n"
        f"Phone: {phone}\n"
        f"Total: {app.config['CURRENCY']} {total_price:.2f}\n"
        f"Please confirm my order."
    )


# -----------------------------
# Base HTML
# -----------------------------
BASE_TEMPLATE = '''
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }} - Muffin House</title>
    <style>
        :root {
            --bg: #fff9f3;
            --bg-soft: #fff4ea;
            --card: #ffffff;
            --ink: #2b2118;
            --muted: #6f6257;
            --brand: #9a572b;
            --brand-dark: #7c421d;
            --line: #ecdacd;
            --success-bg: #e8f8ee;
            --success-text: #1c6c39;
            --warn-bg: #fff4d9;
            --warn-text: #7c5b00;
            --danger-bg: #fde8e8;
            --danger-text: #902222;
            --shadow: 0 12px 32px rgba(79, 42, 14, 0.08);
            --whatsapp: #25D366;
        }
        * { box-sizing: border-box; }
        body { margin: 0; font-family: Inter, Arial, sans-serif; color: var(--ink); background: linear-gradient(180deg, #fffaf5 0%, #fff6ef 100%); }
        a { color: inherit; }
        .topbar { position: sticky; top: 0; z-index: 50; backdrop-filter: blur(10px); background: rgba(86, 47, 21, 0.95); color: white; box-shadow: 0 6px 18px rgba(0,0,0,0.12); }
        .topbar-inner { max-width: 1180px; margin: 0 auto; padding: 16px 20px; display: flex; align-items: center; justify-content: space-between; gap: 20px; }
        .brand { display: flex; align-items: center; gap: 12px; text-decoration: none; font-weight: 800; font-size: 1.7rem; }
        .brand-badge { width: 44px; height: 44px; border-radius: 14px; display: grid; place-items: center; background: rgba(255,255,255,0.15); overflow: hidden; }
        nav { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
        nav a { text-decoration: none; font-weight: 700; padding: 10px 14px; border-radius: 999px; }
        nav a:hover { background: rgba(255,255,255,0.12); }
        .container { max-width: 1180px; margin: 28px auto; padding: 0 20px 24px; }
        .hero { display: grid; grid-template-columns: 1.05fr 0.95fr; gap: 24px; align-items: stretch; margin-bottom: 28px; }
        .hero-main, .hero-image, .panel, .card { background: var(--card); border: 1px solid rgba(236, 218, 205, 0.8); border-radius: 24px; box-shadow: var(--shadow); }
        .hero-main { padding: 38px; background: linear-gradient(135deg, #fffaf6 0%, #fff4ea 100%); }
        .hero-kicker { display: inline-block; background: #fff0e0; color: #8d4d1f; padding: 8px 12px; border-radius: 999px; font-size: 0.9rem; font-weight: 700; margin-bottom: 18px; }
        .hero h1 { margin: 0 0 14px; font-size: clamp(2rem, 4vw, 3.2rem); line-height: 1.05; }
        .hero p { color: var(--muted); font-size: 1.05rem; line-height: 1.7; margin-bottom: 18px; }
        .hero-actions { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 20px; }
        .hero-image { overflow: hidden; }
        .hero-image img { width: 100%; height: 100%; min-height: 380px; object-fit: cover; display: block; }
        .btn { border: none; padding: 13px 18px; border-radius: 14px; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; gap: 8px; font-weight: 800; }
        .btn-primary { background: var(--brand); color: white; }
        .btn-primary:hover { background: var(--brand-dark); }
        .btn-secondary { background: #3e3b39; color: white; }
        .btn-light { background: #fff; color: var(--ink); border: 1px solid var(--line); }
        .btn-whatsapp { background: var(--whatsapp); color: white; }
        .section-title { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin: 28px 0 16px; }
        .section-title h2 { margin: 0; font-size: 1.8rem; }
        .section-title p { margin: 0; color: var(--muted); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 18px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 16px; margin-bottom: 18px; }
        .stat-card { background: white; border: 1px solid var(--line); border-radius: 18px; padding: 18px; box-shadow: var(--shadow); }
        .stat-card strong { display: block; font-size: 1.7rem; margin-bottom: 6px; }
        .card { overflow: hidden; }
        .card-body { padding: 18px; }
        .feature-card { padding: 22px; }
        .feature-icon { width: 48px; height: 48px; display: grid; place-items: center; background: #fff0e0; color: #8d4d1f; border-radius: 14px; margin-bottom: 14px; font-size: 1.25rem; }
        .menu-image { width: 100%; height: 220px; object-fit: cover; display: block; background: #f3ece5; }
        .pill, .coming-soon-pill, .available-pill { display: inline-block; padding: 6px 10px; border-radius: 999px; font-size: 0.82rem; font-weight: 700; margin-bottom: 10px; }
        .pill { background: #fff0e0; color: #8c4a1d; }
        .coming-soon-pill { background: #efefef; color: #555; }
        .available-pill { background: #e7f7eb; color: #1d6b35; }
        .price { font-size: 1.3rem; font-weight: 800; margin: 10px 0 16px; }
        .panel { padding: 24px; margin-bottom: 22px; }
        .flash { padding: 14px 16px; border-radius: 14px; margin-bottom: 16px; font-weight: 700; }
        .success { background: var(--success-bg); color: var(--success-text); }
        .warning { background: var(--warn-bg); color: var(--warn-text); }
        .danger { background: var(--danger-bg); color: var(--danger-text); }
        label { display: block; font-weight: 700; margin: 6px 0 6px; }
        input, select, textarea { width: 100%; padding: 12px 14px; border: 1px solid #d9c6b7; border-radius: 14px; background: #fff; font: inherit; margin-bottom: 14px; }
        input:focus, select:focus, textarea:focus { outline: none; border-color: #b56d3d; box-shadow: 0 0 0 4px rgba(181, 109, 61, 0.12); }
        .row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
        .muted { color: var(--muted); }
        .summary-box { background: #fff8f2; border: 1px dashed #d8bba4; border-radius: 16px; padding: 16px; margin-top: 10px; }
        .order-summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 12px; }
        .order-summary-mini { background: white; border: 1px solid #eee2d8; border-radius: 14px; padding: 12px; }
        .order-summary-mini strong { display: block; margin-bottom: 6px; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 18px; overflow: hidden; }
        th, td { padding: 14px 12px; border-bottom: 1px solid #eee2d8; text-align: left; vertical-align: top; }
        th { background: #fff4ea; }
        .status { display: inline-block; padding: 7px 10px; border-radius: 999px; font-weight: 800; font-size: 0.8rem; background: #f3ece5; }
        .admin-card { padding: 20px; margin-bottom: 16px; }
        .footer { max-width: 1180px; margin: 14px auto 34px; color: #7a6d62; padding: 0 20px; text-align: center; }
        .tiny { font-size: 0.9rem; }
        .show-password-box { display: flex; gap: 8px; align-items: center; margin-bottom: 14px; }
        .show-password-box input { width: auto; margin: 0; }
        .quick-links { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 14px; }
        .faq-item { border-top: 1px solid var(--line); padding: 14px 0; }
        .faq-item:first-child { border-top: none; }
        @media (max-width: 860px) {
            .hero { grid-template-columns: 1fr; }
            .row { grid-template-columns: 1fr; }
            .topbar-inner { flex-direction: column; align-items: flex-start; }
            .order-summary-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <header class="topbar">
        <div class="topbar-inner">
            <a class="brand" href="{{ url_for('home') }}">
                <span class="brand-badge">
                    <img src="{{ logo_path }}" alt="Muffin House logo" style="width:100%;height:100%;object-fit:contain;padding:4px;background:white;border-radius:12px;">
                </span>
                <span>Muffin House</span>
            </a>
            <nav>
                <a href="{{ url_for('home') }}">Home</a>
                <a href="{{ url_for('menu') }}">Menu</a>
                {% if session.get('user_id') %}
                    <a href="{{ url_for('dashboard') }}">My Orders</a>
                    <a href="{{ url_for('profile') }}">Profile</a>
                    <a href="{{ url_for('verify_phone') }}">Verify Phone</a>
                    {% if session.get('is_admin') %}
                        <a href="{{ url_for('admin_panel') }}">Admin</a>
                        <a href="{{ url_for('admin_menu') }}">Manage Menu</a>
                    {% endif %}
                    <a href="{{ url_for('logout') }}">Logout</a>
                {% else %}
                    <a href="{{ url_for('register') }}">Register</a>
                    <a href="{{ url_for('login') }}">Login</a>
                {% endif %}
            </nav>
        </div>
    </header>

    <main class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="flash {{ category }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        {{ body|safe }}
    </main>

    <footer class="footer tiny">
        Phase 5 • Final polish • Admin summaries • FAQ • Contact section • Delivered status • WhatsApp buttons
    </footer>

    <script>
        function togglePassword(inputId, checkboxId) {
            const input = document.getElementById(inputId);
            const checkbox = document.getElementById(checkboxId);
            if (!input || !checkbox) return;
            input.type = checkbox.checked ? 'text' : 'password';
        }

        function updateOrderSummary() {
            const quantityInput = document.getElementById('quantity');
            const fulfillmentSelect = document.getElementById('fulfillment_type');
            const unitPriceEl = document.getElementById('js-unit-price');
            const deliveryFeeEl = document.getElementById('js-delivery-fee');
            const totalEl = document.getElementById('js-total-price');
            if (!quantityInput || !fulfillmentSelect) return;
            const unitPrice = parseFloat(quantityInput.dataset.unitPrice || '0');
            const flatDelivery = parseFloat(quantityInput.dataset.deliveryFee || '0');
            const quantity = Math.max(parseInt(quantityInput.value || '1') || 1, 1);
            const fulfillmentType = fulfillmentSelect.value || 'Pickup';
            const subtotal = unitPrice * quantity;
            const deliveryFee = fulfillmentType === 'Delivery' ? flatDelivery : 0;
            const total = subtotal + deliveryFee;
            if (unitPriceEl) unitPriceEl.textContent = unitPrice.toFixed(2);
            if (deliveryFeeEl) deliveryFeeEl.textContent = deliveryFee.toFixed(2);
            if (totalEl) totalEl.textContent = total.toFixed(2);
        }

        document.addEventListener('DOMContentLoaded', function () {
            const quantityInput = document.getElementById('quantity');
            const fulfillmentSelect = document.getElementById('fulfillment_type');
            if (quantityInput) quantityInput.addEventListener('input', updateOrderSummary);
            if (fulfillmentSelect) fulfillmentSelect.addEventListener('change', updateOrderSummary);
            updateOrderSummary();
        });
    </script>
</body>
</html>
'''


def render_page(title, body_template, **context):
    body = render_template_string(body_template, **context)
    return render_template_string(BASE_TEMPLATE, title=title, body=body, **context)


# -----------------------------
# Routes
# -----------------------------
@app.route('/')
def home():
    conn = get_db_connection()
    featured = conn.execute('SELECT * FROM menu_items ORDER BY is_available DESC, id DESC LIMIT 4').fetchall()
    order_count = conn.execute('SELECT COUNT(*) AS total FROM orders').fetchone()['total']
    item_count = conn.execute('SELECT COUNT(*) AS total FROM menu_items').fetchone()['total']
    available_count = conn.execute('SELECT COUNT(*) AS total FROM menu_items WHERE is_available = 1').fetchone()['total']
    delivered_count = conn.execute("SELECT COUNT(*) AS total FROM orders WHERE order_status = 'Delivered'").fetchone()['total']
    conn.close()

    general_whatsapp_url = build_whatsapp_url('Hello Muffin House, I want to ask about your lemon muffins and delivery options.')

    body = '''
    <section class="hero">
        <div class="hero-main">
            <span class="hero-kicker">Fresh homemade muffins • Lemon flavor available now</span>
            <h1>Fresh lemon muffins, free UNZA delivery, quick WhatsApp contact</h1>
            <p>
                Muffin House makes ordering simple: register, verify your phone, place your order,
                and track the delivery status from pending all the way to delivered.
            </p>
            <div class="hero-actions">
                <a class="btn btn-primary" href="{{ url_for('menu') }}">Order Lemon Muffins</a>
                <a class="btn btn-whatsapp" href="{{ general_whatsapp_url }}" target="_blank">WhatsApp Us</a>
            </div>
            <div class="summary-box">
                <strong>Current availability:</strong> Only lemon muffins can be ordered right now at ZMW 5 each,
                with free delivery within UNZA campus. Other flavors remain visible as coming soon.
            </div>
        </div>
        <div class="hero-image">
            <img src="{{ home_image }}" alt="Homemade lemon muffins">
        </div>
    </section>

    <section>
        <div class="section-title">
            <div>
                <h2>Business snapshot</h2>
                <p>Quick visibility into the current setup.</p>
            </div>
        </div>
        <div class="grid">
            <div class="card feature-card"><div class="feature-icon">🧁</div><h3>{{ item_count }} menu items</h3><p class="muted">All listed flavors, including coming soon items.</p></div>
            <div class="card feature-card"><div class="feature-icon">🍋</div><h3>{{ available_count }} available now</h3><p class="muted">Currently the live flavor is lemon only.</p></div>
            <div class="card feature-card"><div class="feature-icon">📦</div><h3>{{ order_count }} orders</h3><p class="muted">Orders already captured by the system.</p></div>
            <div class="card feature-card"><div class="feature-icon">✅</div><h3>{{ delivered_count }} delivered</h3><p class="muted">Completed deliveries recorded by the admin team.</p></div>
        </div>
    </section>

    <section>
        <div class="section-title">
            <div>
                <h2>Available and upcoming flavors</h2>
                <p>Customers can clearly see what is live and what is not yet ready.</p>
            </div>
        </div>
        <div class="grid">
            {% for item in featured %}
                <article class="card">
                    <img class="menu-image" src="{{ item['image_url'] or home_image }}" alt="{{ item['name'] }}">
                    <div class="card-body">
                        {% if item['is_available'] %}
                            <span class="available-pill">Available Now</span>
                        {% else %}
                            <span class="coming-soon-pill">Coming Soon</span>
                        {% endif %}
                        <h3>{{ item['name'] }}</h3>
                        <p class="muted">{{ item['description'] }}</p>
                        {% if item['name'] == 'Lemon Muffin' %}
                            <p class="muted"><strong>Price:</strong> ZMW 5 each • <strong>Delivery:</strong> Free within UNZA campus</p>
                        {% endif %}
                        <div class="price">ZMW {{ '%.2f'|format(item['price']) }}</div>
                        {% if item['is_available'] %}
                            <a class="btn btn-primary" href="{{ url_for('place_order', item_id=item['id']) }}">Order This</a>
                        {% else %}
                            <button class="btn btn-light" disabled>Coming Soon</button>
                        {% endif %}
                    </div>
                </article>
            {% endfor %}
        </div>
    </section>

    <section class="panel">
        <div class="section-title">
            <div>
                <h2>About & Contact</h2>
                <p>Simple local delivery for UNZA customers.</p>
            </div>
        </div>
        <div class="row">
            <div>
                <p class="muted">
                    Muffin House is built around simple ordering, affordable pricing, and fast student-friendly delivery.
                    Right now the focus is lemon muffins with free delivery within UNZA campus.
                </p>
            </div>
            <div>
                <p><strong>Business name:</strong> {{ business_name }}</p>
                <p><strong>WhatsApp:</strong> {{ business_phone }}</p>
                <a class="btn btn-whatsapp" href="{{ general_whatsapp_url }}" target="_blank">Chat on WhatsApp</a>
            </div>
        </div>
    </section>

    <section class="panel">
        <div class="section-title">
            <div>
                <h2>FAQ</h2>
                <p>Quick answers for customers.</p>
            </div>
        </div>
        <div class="faq-item">
            <strong>Which muffin flavor is available right now?</strong>
            <p class="muted">Only lemon muffin is currently available for ordering.</p>
        </div>
        <div class="faq-item">
            <strong>How much is one lemon muffin?</strong>
            <p class="muted">One lemon muffin costs ZMW 5.</p>
        </div>
        <div class="faq-item">
            <strong>Is delivery free?</strong>
            <p class="muted">Yes. Delivery is free within UNZA campus.</p>
        </div>
        <div class="faq-item">
            <strong>Do I need to verify my phone before ordering?</strong>
            <p class="muted">Yes. Phone verification is required before an order can be placed.</p>
        </div>
    </section>
    '''
    return render_page(
        'Home',
        body,
        featured=featured,
        item_count=item_count,
        available_count=available_count,
        order_count=order_count,
        delivered_count=delivered_count,
        home_image=HOME_IMAGE_PATH,
        general_whatsapp_url=general_whatsapp_url,
        business_name=app.config['BUSINESS_NAME'],
        business_phone=app.config['BUSINESS_PHONE'],
        logo_path=app.config['LOGO_PATH']
    )


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not validate_csrf():
            abort(400, description='Invalid CSRF token.')

        full_name = sanitize_text(request.form.get('full_name'), 120)
        username = sanitize_text(request.form.get('username'), 50)
        email = sanitize_text(request.form.get('email'), 120).lower()
        password = request.form.get('password', '')
        room_number = sanitize_text(request.form.get('room_number'), 30)
        phone = sanitize_text(request.form.get('phone'), 30)

        if not full_name or not username or not email or not password or not phone:
            flash('Full name, username, email, password, and phone are required.', 'danger')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return redirect(url_for('register'))

        conn = get_db_connection()
        try:
            cur = conn.execute('''
                INSERT INTO users (
                    full_name, username, email, password_hash,
                    room_number, phone, phone_verified, is_admin, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                full_name,
                username,
                email,
                generate_password_hash(password),
                room_number,
                phone,
                0,
                0,
                datetime.utcnow().isoformat()
            ))
            user_id = cur.lastrowid
            conn.commit()
            conn.close()
            create_otp_for_user(user_id, phone)
            flash('Account created. OTP generated. Check the terminal for the test OTP code, then verify your phone.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('Username or email already exists.', 'danger')

    body = '''
    <section class="panel">
        <h1>Create Account</h1>
        <p class="muted">Register, then verify the phone number using OTP before ordering.</p>
        <form method="post">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <label>Full name *</label>
            <input name="full_name" required>

            <div class="row">
                <div>
                    <label>Username *</label>
                    <input name="username" required>
                </div>
                <div>
                    <label>Email *</label>
                    <input type="email" name="email" required>
                </div>
            </div>

            <div class="row">
                <div>
                    <label>Password *</label>
                    <input id="register_password" type="password" name="password" required>
                    <label class="show-password-box">
                        <input id="show_register_password" type="checkbox" onclick="togglePassword('register_password','show_register_password')">
                        <span>Show password</span>
                    </label>
                </div>
                <div>
                    <label>Phone *</label>
                    <input name="phone" placeholder="e.g. 097xxxxxxx" required>
                </div>
            </div>

            <label>Default room number</label>
            <input name="room_number">

            <button class="btn btn-primary" type="submit">Register</button>
        </form>
    </section>
    '''
    return render_page('Register', body, logo_path=app.config['LOGO_PATH'])


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not validate_csrf():
            abort(400, description='Invalid CSRF token.')

        username = sanitize_text(request.form.get('username'), 50)
        password = request.form.get('password', '')

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            flash('Welcome back.', 'success')
            return redirect(url_for('admin_panel' if user['is_admin'] else 'dashboard'))

        flash('Invalid username or password.', 'danger')

    body = '''
    <section class="panel" style="max-width: 620px; margin: 0 auto;">
        <h1>Login</h1>
        <p class="muted">Login and continue with ordering or phone verification.</p>
        <form method="post">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <label>Username</label>
            <input name="username" required>

            <label>Password</label>
            <input id="login_password" type="password" name="password" required>
            <label class="show-password-box">
                <input id="show_login_password" type="checkbox" onclick="togglePassword('login_password','show_login_password')">
                <span>Show password</span>
            </label>

            <button class="btn btn-primary" type="submit">Login</button>
        </form>
        <div class="summary-box tiny">
            Starter admin login for testing only: <strong>admin</strong> / <strong>ChangeMe123!</strong>
        </div>
    </section>
    '''
    return render_page('Login', body, logo_path=app.config['LOGO_PATH'])


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


@app.route('/verify-phone', methods=['GET', 'POST'])
@login_required
def verify_phone():
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if request.method == 'POST':
        if not validate_csrf():
            conn.close()
            abort(400, description='Invalid CSRF token.')

        action = sanitize_text(request.form.get('action'), 20)

        if action == 'send':
            phone = sanitize_text(request.form.get('phone'), 30) or user['phone']
            if not phone:
                conn.close()
                flash('Please provide a phone number.', 'danger')
                return redirect(url_for('verify_phone'))

            conn.execute('UPDATE users SET phone = ?, phone_verified = 0 WHERE id = ?', (phone, session['user_id']))
            conn.commit()
            conn.close()
            create_otp_for_user(session['user_id'], phone)
            flash('OTP sent in testing mode. Check the terminal where Flask is running and enter the code here.', 'success')
            return redirect(url_for('verify_phone'))

        if action == 'verify':
            otp_code = sanitize_text(request.form.get('otp_code'), 10)
            latest = conn.execute('''
                SELECT * FROM otp_codes
                WHERE user_id = ? AND is_used = 0
                ORDER BY id DESC
                LIMIT 1
            ''', (session['user_id'],)).fetchone()

            if not latest:
                conn.close()
                flash('No active OTP found. Send a new code first.', 'danger')
                return redirect(url_for('verify_phone'))

            if datetime.utcnow() > datetime.fromisoformat(latest['expires_at']):
                conn.close()
                flash('OTP expired. Send a new code.', 'danger')
                return redirect(url_for('verify_phone'))

            if otp_code != latest['otp_code']:
                conn.close()
                flash('Invalid OTP code.', 'danger')
                return redirect(url_for('verify_phone'))

            conn.execute('UPDATE otp_codes SET is_used = 1 WHERE id = ?', (latest['id'],))
            conn.execute('UPDATE users SET phone_verified = 1 WHERE id = ?', (session['user_id'],))
            conn.commit()
            conn.close()
            flash('Phone number verified successfully.', 'success')
            return redirect(url_for('profile'))

    conn.close()
    body = '''
    <section class="panel" style="max-width: 760px; margin: 0 auto;">
        <h1>Verify Phone Number</h1>
        <p class="muted">This version supports OTP verification immediately for testing. The OTP appears in the Flask terminal. Real SMS can be connected later.</p>

        <div class="summary-box">
            <p><strong>Current phone:</strong> {{ user['phone'] or 'Not set' }}</p>
            <p><strong>Verification status:</strong> {{ 'Verified' if user['phone_verified'] else 'Not verified' }}</p>
            <p><strong>OTP validity:</strong> {{ otp_minutes }} minutes</p>
        </div>

        <form method="post" style="margin-top: 18px;">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <input type="hidden" name="action" value="send">
            <label>Phone number</label>
            <input name="phone" value="{{ user['phone'] or '' }}" required>
            <button class="btn btn-primary" type="submit">Send OTP</button>
        </form>

        <form method="post" style="margin-top: 18px;">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <input type="hidden" name="action" value="verify">
            <label>Enter OTP code</label>
            <input name="otp_code" placeholder="6-digit code" required>
            <button class="btn btn-secondary" type="submit">Verify Phone</button>
        </form>
    </section>
    '''
    return render_page('Verify Phone', body, user=user, otp_minutes=app.config['OTP_EXPIRY_MINUTES'], logo_path=app.config['LOGO_PATH'])


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if request.method == 'POST':
        if not validate_csrf():
            conn.close()
            abort(400, description='Invalid CSRF token.')

        full_name = sanitize_text(request.form.get('full_name'), 120)
        email = sanitize_text(request.form.get('email'), 120).lower()
        room_number = sanitize_text(request.form.get('room_number'), 30)
        phone = sanitize_text(request.form.get('phone'), 30)

        if not full_name or not email:
            conn.close()
            flash('Full name and email are required.', 'danger')
            return redirect(url_for('profile'))

        try:
            conn.execute('''
                UPDATE users
                SET full_name = ?, email = ?, room_number = ?, phone = ?
                WHERE id = ?
            ''', (full_name, email, room_number, phone, session['user_id']))
            conn.commit()
            flash('Profile updated successfully.', 'success')
            return redirect(url_for('profile'))
        except sqlite3.IntegrityError:
            flash('That email is already being used by another account.', 'danger')
        finally:
            conn.close()

    body = '''
    <section class="panel" style="max-width: 760px; margin: 0 auto;">
        <h1>My Profile</h1>
        <p class="muted">Update your saved contact and delivery details.</p>
        <form method="post">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <label>Full name</label>
            <input name="full_name" value="{{ user['full_name'] }}" required>

            <div class="row">
                <div>
                    <label>Email</label>
                    <input type="email" name="email" value="{{ user['email'] }}" required>
                </div>
                <div>
                    <label>Phone</label>
                    <input name="phone" value="{{ user['phone'] or '' }}">
                </div>
            </div>

            <label>Default room number</label>
            <input name="room_number" value="{{ user['room_number'] or '' }}">

            <div class="summary-box">
                <strong>Phone verification:</strong> {{ 'Verified' if user['phone_verified'] else 'Not verified' }}
                {% if not user['phone_verified'] %} • <a href="{{ url_for('verify_phone') }}">Verify now</a>{% endif %}
            </div>

            <div style="margin-top: 14px;">
                <button class="btn btn-primary" type="submit">Save Profile</button>
            </div>
        </form>
    </section>
    '''
    return render_page('Profile', body, user=user, logo_path=app.config['LOGO_PATH'])


@app.route('/menu')
def menu():
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM menu_items ORDER BY is_available DESC, id DESC').fetchall()
    conn.close()

    general_whatsapp_url = build_whatsapp_url('Hello Muffin House, I would like to ask about your muffins.')

    body = '''
    <section class="section-title">
        <div>
            <h2>Menu</h2>
            <p>Only lemon flavor is available right now at ZMW 5 each. Delivery is free within UNZA campus. Other flavors are listed as coming soon.</p>
        </div>
        <a class="btn btn-whatsapp" href="{{ general_whatsapp_url }}" target="_blank">Ask on WhatsApp</a>
    </section>

    <section class="grid">
        {% for item in items %}
            <article class="card">
                <img class="menu-image" src="{{ item['image_url'] or home_image }}" alt="{{ item['name'] }}">
                <div class="card-body">
                    {% if item['is_available'] %}
                        <span class="available-pill">Available Now</span>
                    {% else %}
                        <span class="coming-soon-pill">Coming Soon</span>
                    {% endif %}
                    <h3>{{ item['name'] }}</h3>
                    <p class="muted">{{ item['description'] }}</p>
                    {% if item['name'] == 'Lemon Muffin' %}
                        <p class="muted"><strong>Price:</strong> ZMW 5 each • <strong>Delivery:</strong> Free within UNZA campus</p>
                    {% endif %}
                    <div class="price">ZMW {{ '%.2f'|format(item['price']) }}</div>
                    {% if item['is_available'] %}
                        {% if session.get('user_id') %}
                            <a class="btn btn-primary" href="{{ url_for('place_order', item_id=item['id']) }}">Order</a>
                        {% else %}
                            <a class="btn btn-primary" href="{{ url_for('login') }}">Login to order</a>
                        {% endif %}
                    {% else %}
                        <button class="btn btn-light" disabled>Coming Soon</button>
                    {% endif %}
                </div>
            </article>
        {% endfor %}
    </section>
    '''
    return render_page('Menu', body, items=items, home_image=HOME_IMAGE_PATH, general_whatsapp_url=general_whatsapp_url, logo_path=app.config['LOGO_PATH'])


@app.route('/order/<int:item_id>', methods=['GET', 'POST'])
@login_required
@verified_phone_required
def place_order(item_id):
    conn = get_db_connection()
    item = conn.execute('SELECT * FROM menu_items WHERE id = ? AND is_available = 1', (item_id,)).fetchone()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if not item:
        conn.close()
        abort(404)

    if request.method == 'POST':
        if not validate_csrf():
            conn.close()
            abort(400, description='Invalid CSRF token.')

        try:
            quantity = int(request.form.get('quantity', '1'))
        except ValueError:
            quantity = 0

        fulfillment_type = sanitize_text(request.form.get('fulfillment_type'), 20)
        room_number = sanitize_text(request.form.get('room_number'), 30)
        phone = sanitize_text(request.form.get('phone'), 30)
        special_instructions = sanitize_text(request.form.get('special_instructions'), 400)

        if quantity < 1 or quantity > 100:
            conn.close()
            flash('Quantity must be between 1 and 100.', 'danger')
            return redirect(url_for('place_order', item_id=item_id))

        if fulfillment_type not in ['Pickup', 'Delivery']:
            conn.close()
            flash('Invalid fulfillment type.', 'danger')
            return redirect(url_for('place_order', item_id=item_id))

        if fulfillment_type == 'Delivery' and not room_number:
            conn.close()
            flash('Room number is required for delivery.', 'danger')
            return redirect(url_for('place_order', item_id=item_id))

        _, delivery_fee, total_price = calculate_totals(item['price'], quantity, fulfillment_type)

        cur = conn.execute('''
            INSERT INTO orders (
                user_id, item_id, quantity, fulfillment_type, room_number, phone,
                special_instructions, unit_price, delivery_fee, total_price,
                order_status, payment_status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session['user_id'],
            item_id,
            quantity,
            fulfillment_type,
            room_number,
            phone,
            special_instructions,
            item['price'],
            delivery_fee,
            total_price,
            'Pending',
            'Pending',
            datetime.utcnow().isoformat()
        ))
        order_id = cur.lastrowid
        conn.commit()
        conn.close()

        flash('Order placed successfully.', 'success')
        return redirect(url_for('order_success', order_id=order_id))

    _, _, preview_total = calculate_totals(item['price'], 1, 'Pickup')
    pre_order_whatsapp_url = build_whatsapp_url(f"Hello Muffin House, I want to ask about ordering {item['name']}.")

    body = '''
    <section class="panel" style="max-width: 900px; margin: 0 auto;">
        <h1>Order {{ item['name'] }}</h1>
        <div class="row">
            <div>
                <img class="menu-image" style="height: 280px; border-radius: 18px;" src="{{ item['image_url'] or home_image }}" alt="{{ item['name'] }}">
            </div>
            <div>
                <span class="available-pill">Available Now</span>
                <p class="muted">{{ item['description'] }}</p>
                <div class="summary-box">
                    <strong>Live order calculator</strong>
                    <div class="order-summary-grid">
                        <div class="order-summary-mini"><strong>Unit price</strong>{{ currency }} <span id="js-unit-price">{{ '%.2f'|format(item['price']) }}</span></div>
                        <div class="order-summary-mini"><strong>Delivery fee</strong>{{ currency }} <span id="js-delivery-fee">0.00</span></div>
                        <div class="order-summary-mini"><strong>Total</strong>{{ currency }} <span id="js-total-price">{{ '%.2f'|format(preview_total) }}</span></div>
                    </div>
                </div>
            </div>
        </div>

        <form method="post" style="margin-top: 18px;">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <div class="row">
                <div>
                    <label>Quantity</label>
                    <input id="quantity" data-unit-price="{{ item['price'] }}" data-delivery-fee="{{ delivery_fee }}" type="number" name="quantity" min="1" max="100" value="1" required>
                </div>
                <div>
                    <label>Fulfillment type</label>
                    <select id="fulfillment_type" name="fulfillment_type" required>
                        <option value="Pickup">Pickup</option>
                        <option value="Delivery">Delivery</option>
                    </select>
                </div>
            </div>
            <div class="row">
                <div>
                    <label>Room number (required for delivery)</label>
                    <input name="room_number" value="{{ user['room_number'] or '' }}">
                </div>
                <div>
                    <label>Phone number</label>
                    <input name="phone" value="{{ user['phone'] or '' }}">
                </div>
            </div>
            <label>Special instructions</label>
            <textarea name="special_instructions" rows="4" placeholder="Example: Deliver after 18:00, call when outside, leave at reception."></textarea>
            <div class="quick-links">
                <button class="btn btn-primary" type="submit">Submit Order</button>
                <a class="btn btn-whatsapp" href="{{ pre_order_whatsapp_url }}" target="_blank">Ask Before Ordering</a>
                <a class="btn btn-light" href="{{ url_for('menu') }}">Back to Menu</a>
            </div>
        </form>
    </section>
    '''
    return render_page(
        'Place Order',
        body,
        item=item,
        user=user,
        preview_total=preview_total,
        delivery_fee=app.config['DELIVERY_FEE'],
        home_image=HOME_IMAGE_PATH,
        currency=app.config['CURRENCY'],
        pre_order_whatsapp_url=pre_order_whatsapp_url,
        logo_path=app.config['LOGO_PATH']
    )


@app.route('/order-success/<int:order_id>')
@login_required
def order_success(order_id):
    conn = get_db_connection()
    order = conn.execute('''
        SELECT o.*, m.name AS item_name
        FROM orders o
        JOIN menu_items m ON o.item_id = m.id
        WHERE o.id = ? AND o.user_id = ?
    ''', (order_id, session['user_id'])).fetchone()
    conn.close()

    if not order:
        abort(404)

    whatsapp_message = build_order_whatsapp_message(
        order['item_name'],
        order['quantity'],
        order['fulfillment_type'],
        order['room_number'],
        order['phone'],
        order['total_price']
    )
    whatsapp_url = build_whatsapp_url(whatsapp_message)

    body = '''
    <section class="panel" style="max-width: 760px; margin: 0 auto; text-align: center;">
        <h1>Order Received</h1>
        <p class="muted">Your order has been saved successfully. You can also send it to the business on WhatsApp for faster confirmation.</p>

        <div class="summary-box" style="text-align: left; margin-top: 18px;">
            <p><strong>Order ID:</strong> #{{ order['id'] }}</p>
            <p><strong>Item:</strong> {{ order['item_name'] }}</p>
            <p><strong>Quantity:</strong> {{ order['quantity'] }}</p>
            <p><strong>Fulfillment:</strong> {{ order['fulfillment_type'] }}</p>
            <p><strong>Room:</strong> {{ order['room_number'] or 'N/A' }}</p>
            <p><strong>Phone:</strong> {{ order['phone'] or 'N/A' }}</p>
            <p><strong>Total:</strong> {{ currency }} {{ '%.2f'|format(order['total_price']) }}</p>
        </div>

        <div class="quick-links" style="justify-content: center; margin-top: 18px;">
            <a class="btn btn-whatsapp" href="{{ whatsapp_url }}" target="_blank">Send on WhatsApp</a>
            <a class="btn btn-primary" href="{{ url_for('dashboard') }}">Go to My Orders</a>
            <a class="btn btn-light" href="{{ url_for('menu') }}">Order Again</a>
        </div>
    </section>
    '''
    return render_page('Order Success', body, order=order, whatsapp_url=whatsapp_url, currency=app.config['CURRENCY'], logo_path=app.config['LOGO_PATH'])


@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    orders = conn.execute('''
        SELECT o.*, m.name AS item_name
        FROM orders o
        JOIN menu_items m ON o.item_id = m.id
        WHERE o.user_id = ?
        ORDER BY o.id DESC
    ''', (session['user_id'],)).fetchall()
    user = conn.execute('SELECT phone_verified FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    body = '''
    <section class="section-title">
        <div>
            <h2>My Orders</h2>
            <p>Track delivery progress and payment status from one place.</p>
        </div>
        <a class="btn btn-primary" href="{{ url_for('menu') }}">Order More</a>
    </section>

    {% if not user['phone_verified'] %}
        <section class="panel">
            <p><strong>Phone not verified.</strong> You need OTP verification before placing new orders.</p>
            <a class="btn btn-secondary" href="{{ url_for('verify_phone') }}">Verify Phone</a>
        </section>
    {% endif %}

    <section class="panel">
        {% if orders %}
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Item</th>
                        <th>Qty</th>
                        <th>Type</th>
                        <th>Room</th>
                        <th>Unit</th>
                        <th>Delivery Fee</th>
                        <th>Total</th>
                        <th>Status</th>
                        <th>Payment</th>
                        <th>Date</th>
                    </tr>
                </thead>
                <tbody>
                    {% for order in orders %}
                    <tr>
                        <td>#{{ order['id'] }}</td>
                        <td>{{ order['item_name'] }}</td>
                        <td>{{ order['quantity'] }}</td>
                        <td>{{ order['fulfillment_type'] }}</td>
                        <td>{{ order['room_number'] or '-' }}</td>
                        <td>{{ currency }} {{ '%.2f'|format(order['unit_price']) }}</td>
                        <td>{{ currency }} {{ '%.2f'|format(order['delivery_fee']) }}</td>
                        <td><strong>{{ currency }} {{ '%.2f'|format(order['total_price']) }}</strong></td>
                        <td><span class="status">{{ order['order_status'] }}</span></td>
                        <td><span class="status">{{ order['payment_status'] }}</span></td>
                        <td>{{ order['created_at'][:19].replace('T', ' ') }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <p>No orders yet.</p>
            <a class="btn btn-primary" href="{{ url_for('menu') }}">Browse Menu</a>
        {% endif %}
    </section>
    '''
    return render_page('Dashboard', body, orders=orders, user=user, currency=app.config['CURRENCY'], logo_path=app.config['LOGO_PATH'])


@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_panel():
    conn = get_db_connection()

    if request.method == 'POST':
        if not validate_csrf():
            conn.close()
            abort(400, description='Invalid CSRF token.')

        order_id = request.form.get('order_id')
        order_status = sanitize_text(request.form.get('order_status'), 30)
        payment_status = sanitize_text(request.form.get('payment_status'), 30)

        valid_order_statuses = ['Pending', 'Preparing', 'Out for Delivery', 'Delivered', 'Completed', 'Cancelled']
        valid_payment_statuses = ['Pending', 'Paid', 'Failed']

        if order_status not in valid_order_statuses or payment_status not in valid_payment_statuses:
            conn.close()
            flash('Invalid order update.', 'danger')
            return redirect(url_for('admin_panel'))

        conn.execute('''
            UPDATE orders
            SET order_status = ?, payment_status = ?
            WHERE id = ?
        ''', (order_status, payment_status, order_id))
        conn.commit()
        flash('Order updated successfully.', 'success')

    search = sanitize_text(request.args.get('search'), 80)
    status_filter = sanitize_text(request.args.get('status'), 40)

    base_query = '''
        SELECT o.*, u.full_name, u.username, m.name AS item_name
        FROM orders o
        JOIN users u ON o.user_id = u.id
        JOIN menu_items m ON o.item_id = m.id
        WHERE 1=1
    '''
    params = []

    if search:
        base_query += ' AND (u.full_name LIKE ? OR u.username LIKE ? OR m.name LIKE ? OR o.phone LIKE ? OR o.room_number LIKE ?)'
        like = f'%{search}%'
        params.extend([like, like, like, like, like])

    if status_filter:
        base_query += ' AND o.order_status = ?'
        params.append(status_filter)

    base_query += ' ORDER BY o.id DESC'

    orders = conn.execute(base_query, params).fetchall()

    summary = {
        'total': conn.execute('SELECT COUNT(*) AS total FROM orders').fetchone()['total'],
        'pending': conn.execute("SELECT COUNT(*) AS total FROM orders WHERE order_status = 'Pending'").fetchone()['total'],
        'out_for_delivery': conn.execute("SELECT COUNT(*) AS total FROM orders WHERE order_status = 'Out for Delivery'").fetchone()['total'],
        'delivered': conn.execute("SELECT COUNT(*) AS total FROM orders WHERE order_status = 'Delivered'").fetchone()['total'],
    }
    conn.close()

    body = '''
    <section class="section-title">
        <div>
            <h2>Admin Panel</h2>
            <p>Monitor all incoming orders and update their progress.</p>
        </div>
        <a class="btn btn-light" href="{{ url_for('admin_menu') }}">Manage Menu</a>
    </section>

    <section class="stats-grid">
        <div class="stat-card"><strong>{{ summary['total'] }}</strong><span class="muted">Total Orders</span></div>
        <div class="stat-card"><strong>{{ summary['pending'] }}</strong><span class="muted">Pending</span></div>
        <div class="stat-card"><strong>{{ summary['out_for_delivery'] }}</strong><span class="muted">Out for Delivery</span></div>
        <div class="stat-card"><strong>{{ summary['delivered'] }}</strong><span class="muted">Delivered</span></div>
    </section>

    <section class="panel">
        <form method="get" class="row">
            <div>
                <label>Search orders</label>
                <input name="search" value="{{ search }}" placeholder="Customer, item, phone, room...">
            </div>
            <div>
                <label>Filter by status</label>
                <select name="status">
                    <option value="">All statuses</option>
                    {% for s in ['Pending', 'Preparing', 'Out for Delivery', 'Delivered', 'Completed', 'Cancelled'] %}
                        <option value="{{ s }}" {% if status_filter == s %}selected{% endif %}>{{ s }}</option>
                    {% endfor %}
                </select>
            </div>
            <div class="quick-links">
                <button class="btn btn-primary" type="submit">Apply</button>
                <a class="btn btn-light" href="{{ url_for('admin_panel') }}">Reset</a>
            </div>
        </form>
    </section>

    {% if orders %}
        {% for order in orders %}
            <section class="card admin-card">
                <h3>Order #{{ order['id'] }} — {{ order['item_name'] }}</h3>
                <div class="row">
                    <div>
                        <p><strong>Customer:</strong> {{ order['full_name'] }} ({{ order['username'] }})</p>
                        <p><strong>Quantity:</strong> {{ order['quantity'] }}</p>
                        <p><strong>Fulfillment:</strong> {{ order['fulfillment_type'] }}</p>
                        <p><strong>Room:</strong> {{ order['room_number'] or '-' }}</p>
                        <p><strong>Phone:</strong> {{ order['phone'] or '-' }}</p>
                    </div>
                    <div>
                        <p><strong>Unit price:</strong> {{ currency }} {{ '%.2f'|format(order['unit_price']) }}</p>
                        <p><strong>Delivery fee:</strong> {{ currency }} {{ '%.2f'|format(order['delivery_fee']) }}</p>
                        <p><strong>Total:</strong> {{ currency }} {{ '%.2f'|format(order['total_price']) }}</p>
                        <p><strong>Date:</strong> {{ order['created_at'][:19].replace('T', ' ') }}</p>
                    </div>
                </div>
                <p><strong>Instructions:</strong> {{ order['special_instructions'] or 'None' }}</p>

                <form method="post">
                    <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                    <input type="hidden" name="order_id" value="{{ order['id'] }}">
                    <div class="row">
                        <div>
                            <label>Order status</label>
                            <select name="order_status">
                                {% for s in ['Pending', 'Preparing', 'Out for Delivery', 'Delivered', 'Completed', 'Cancelled'] %}
                                    <option value="{{ s }}" {% if s == order['order_status'] %}selected{% endif %}>{{ s }}</option>
                                {% endfor %}
                            </select>
                        </div>
                        <div>
                            <label>Payment status</label>
                            <select name="payment_status">
                                {% for p in ['Pending', 'Paid', 'Failed'] %}
                                    <option value="{{ p }}" {% if p == order['payment_status'] %}selected{% endif %}>{{ p }}</option>
                                {% endfor %}
                            </select>
                        </div>
                    </div>
                    <button class="btn btn-primary" type="submit">Update Order</button>
                </form>
            </section>
        {% endfor %}
    {% else %}
        <section class="panel"><p>No orders available for the current filter.</p></section>
    {% endif %}
    '''
    return render_page('Admin Panel', body, orders=orders, currency=app.config['CURRENCY'], summary=summary, search=search, status_filter=status_filter, logo_path=app.config['LOGO_PATH'])


@app.route('/admin/menu', methods=['GET', 'POST'])
@admin_required
def admin_menu():
    conn = get_db_connection()

    if request.method == 'POST':
        if not validate_csrf():
            conn.close()
            abort(400, description='Invalid CSRF token.')

        action = sanitize_text(request.form.get('action'), 20)

        if action == 'create':
            name = sanitize_text(request.form.get('name'), 100)
            description = sanitize_text(request.form.get('description'), 300)
            category = sanitize_text(request.form.get('category'), 40) or 'Classic'
            image_url = sanitize_text(request.form.get('image_url'), 500) or HOME_IMAGE_PATH
            try:
                price = float(request.form.get('price', '0'))
            except ValueError:
                price = 0
            is_available = 1 if request.form.get('is_available') == '1' else 0
            is_coming_soon = 1 if request.form.get('is_coming_soon') == '1' else 0

            if not name or price <= 0:
                flash('Name and a valid price are required.', 'danger')
                return redirect(url_for('admin_menu'))

            conn.execute('''
                INSERT INTO menu_items (name, description, price, category, image_url, is_available, is_coming_soon, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (name, description, price, category, image_url, is_available, is_coming_soon, datetime.utcnow().isoformat()))
            conn.commit()
            flash('Menu item added successfully.', 'success')

        elif action == 'toggle':
            item_id = request.form.get('item_id')
            item = conn.execute('SELECT is_available, is_coming_soon FROM menu_items WHERE id = ?', (item_id,)).fetchone()
            if item:
                if item['is_available']:
                    conn.execute('UPDATE menu_items SET is_available = 0, is_coming_soon = 1 WHERE id = ?', (item_id,))
                else:
                    conn.execute('UPDATE menu_items SET is_available = 1, is_coming_soon = 0 WHERE id = ?', (item_id,))
                conn.commit()
                flash('Item availability updated.', 'success')

    items = conn.execute('SELECT * FROM menu_items ORDER BY is_available DESC, id DESC').fetchall()
    conn.close()

    body = '''
    <section class="section-title">
        <div>
            <h2>Manage Menu</h2>
            <p>Add new muffins and control whether they are visible as available or coming soon.</p>
        </div>
    </section>

    <section class="panel">
        <h3>Add Menu Item</h3>
        <form method="post">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <input type="hidden" name="action" value="create">

            <div class="row">
                <div><label>Name</label><input name="name" required></div>
                <div><label>Price</label><input type="number" step="0.01" name="price" required></div>
            </div>

            <div class="row">
                <div><label>Category</label><input name="category" placeholder="Lemon, Chocolate, Vanilla..."></div>
                <div><label>Image URL</label><input name="image_url" placeholder="Leave blank to use muffin photo"></div>
            </div>

            <label>Description</label>
            <textarea name="description" rows="3"></textarea>

            <div class="row">
                <div>
                    <label>Status</label>
                    <select name="is_available">
                        <option value="1">Available now</option>
                        <option value="0">Not available</option>
                    </select>
                </div>
                <div>
                    <label>Coming soon flag</label>
                    <select name="is_coming_soon">
                        <option value="0">No</option>
                        <option value="1">Yes</option>
                    </select>
                </div>
            </div>

            <button class="btn btn-primary" type="submit">Add Item</button>
        </form>
    </section>

    <section class="panel">
        <h3>Existing Menu Items</h3>
        <table>
            <thead>
                <tr><th>ID</th><th>Name</th><th>Category</th><th>Price</th><th>Status</th><th>Action</th></tr>
            </thead>
            <tbody>
                {% for item in items %}
                    <tr>
                        <td>#{{ item['id'] }}</td>
                        <td>{{ item['name'] }}</td>
                        <td>{{ item['category'] or '-' }}</td>
                        <td>{{ currency }} {{ '%.2f'|format(item['price']) }}</td>
                        <td>
                            {% if item['is_available'] %}
                                Available now
                            {% elif item['is_coming_soon'] %}
                                Coming soon
                            {% else %}
                                Hidden
                            {% endif %}
                        </td>
                        <td>
                            <form method="post">
                                <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                                <input type="hidden" name="action" value="toggle">
                                <input type="hidden" name="item_id" value="{{ item['id'] }}">
                                <button class="btn btn-light" type="submit">{{ 'Mark Coming Soon' if item['is_available'] else 'Make Available' }}</button>
                            </form>
                        </td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
    </section>
    '''
    return render_page('Manage Menu', body, items=items, currency=app.config['CURRENCY'], logo_path=app.config['LOGO_PATH'])


@app.errorhandler(403)
def forbidden(_):
    return render_page('Forbidden', '<section class="panel"><h1>403</h1><p>You do not have permission to access this page.</p></section>', logo_path=app.config['LOGO_PATH']), 403


@app.errorhandler(404)
def not_found(_):
    return render_page('Not Found', '<section class="panel"><h1>404</h1><p>The page you requested was not found.</p></section>', logo_path=app.config['LOGO_PATH']), 404


@app.errorhandler(400)
def bad_request(error):
    msg = getattr(error, 'description', 'Bad request.')
    return render_page('Bad Request', f'<section class="panel"><h1>400</h1><p>{msg}</p></section>', logo_path=app.config['LOGO_PATH']), 400


if __name__ == '__main__':
    app.run(debug=True)
