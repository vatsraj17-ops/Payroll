from flask import Flask, render_template, request, redirect, url_for, send_file, abort, flash, session
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
import os
import datetime
import json
from flask_sqlalchemy import SQLAlchemy
from models import (
    db,
    Company,
    Employee,
    PayrollLine,
    User,
    PayrollSubmission,
    Subcontractor,
    SubcontractBill,
    Customer,
    SalesInvoice,
    SalesInvoiceLine,
)
from calc import calculate_payroll
from sqlalchemy import func, inspect, text
import random
from urllib.parse import quote, urlsplit
from functools import wraps
from dotenv import load_dotenv

base_dir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(base_dir, '.env'), override=False)
app = Flask(
    __name__,
    template_folder=os.path.join(base_dir, 'templates'),
    static_folder=os.path.join(base_dir, 'static'),
)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key')
LOGO_FOLDER = os.path.join(base_dir, 'static', 'logos')
os.makedirs(LOGO_FOLDER, exist_ok=True)


def _is_production() -> bool:
    return (
        (os.environ.get('FLASK_ENV') or '').strip().lower() == 'production'
        or (os.environ.get('ENV') or '').strip().lower() == 'production'
        or _is_hosted()
    )


def _is_hosted() -> bool:
    """Detect if running on a hosted platform (DigitalOcean App Platform sets PORT)."""
    return bool((os.environ.get('PORT') or '').strip())


def _get_database_uri() -> str:
    """Resolve DB connection string.

    - Production: set DATABASE_URL (DigitalOcean managed Postgres provides this)
    - Local dev fallback: SQLite file in project directory

    Notes:
    - If DATABASE_URL starts with postgres://, normalize to postgresql:// for SQLAlchemy.
    """
    uri = (os.environ.get('DATABASE_URL') or '').strip()
    if uri:
        if uri.startswith('postgres://'):
            uri = 'postgresql://' + uri[len('postgres://'):]
        return uri

    def _env_first(*keys: str) -> str:
        for key in keys:
            value = (os.environ.get(key) or '').strip()
            if value:
                return value
        return ''

    def _build_postgres_url_from_parts() -> str:
        host = _env_first('PGHOST', 'POSTGRES_HOST', 'POSTGRESQL_HOST')
        user = _env_first('PGUSER', 'POSTGRES_USER', 'POSTGRESQL_USER')
        password = _env_first('PGPASSWORD', 'POSTGRES_PASSWORD', 'POSTGRESQL_PASSWORD')
        dbname = _env_first('PGDATABASE', 'POSTGRES_DB', 'POSTGRESQL_DATABASE')
        port = _env_first('PGPORT', 'POSTGRES_PORT', 'POSTGRESQL_PORT') or '5432'
        sslmode = _env_first('PGSSLMODE', 'POSTGRES_SSLMODE', 'POSTGRESQL_SSLMODE') or ''

        if not (host and user and password and dbname):
            return ''

        base = f"postgresql://{user}:{password}@{host}:{port}/{dbname}"
        if sslmode:
            base = f"{base}?sslmode={sslmode}"
        return base

    # If DATABASE_URL is missing, try to assemble from common Postgres env vars.
    parts_uri = _build_postgres_url_from_parts()
    if parts_uri:
        return parts_uri

    # On hosted platforms, do not silently fall back to SQLite.
    # Multiple instances + ephemeral filesystem will cause inconsistent/vanishing data.
    if _is_hosted() and (os.environ.get('ALLOW_SQLITE_IN_PROD') or '').strip().lower() not in {'1', 'true', 'yes', 'on'}:
        raise RuntimeError('DATABASE_URL must be set (Postgres). Refusing to start with SQLite on a hosted platform.')

    return 'sqlite:///' + os.path.join(base_dir, 'payroll.db')


app.config['SQLALCHEMY_DATABASE_URI'] = _get_database_uri()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Improve reliability with managed Postgres (stale connections can cause intermittent failures).
try:
    _db_uri = str(app.config.get('SQLALCHEMY_DATABASE_URI') or '')
except Exception:
    _db_uri = ''
if _db_uri and not _db_uri.startswith('sqlite'):
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 280,
    }

# Cookie hardening in production (keep local dev working over http://)
if _is_production():
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = True

db.init_app(app)


def _ensure_subcontract_bill_columns() -> None:
    try:
        inspector = inspect(db.engine)
        if 'subcontract_bill' not in inspector.get_table_names():
            return

        statements = [
            'ALTER TABLE subcontract_bill ADD COLUMN IF NOT EXISTS period_start DATE',
            'ALTER TABLE subcontract_bill ADD COLUMN IF NOT EXISTS period_end DATE',
            'ALTER TABLE subcontract_bill ADD COLUMN IF NOT EXISTS due_date DATE',
            'ALTER TABLE subcontract_bill ADD COLUMN IF NOT EXISTS use_hours BOOLEAN DEFAULT 0',
            'ALTER TABLE subcontract_bill ADD COLUMN IF NOT EXISTS hours FLOAT DEFAULT 0',
            'ALTER TABLE subcontract_bill ADD COLUMN IF NOT EXISTS taxable BOOLEAN DEFAULT 1',
            'ALTER TABLE subcontract_bill ADD COLUMN IF NOT EXISTS hours_by_date TEXT',
        ]

        with db.engine.begin() as conn:
            for stmt in statements:
                try:
                    conn.execute(text(stmt))
                except Exception:
                    # Fallback for engines without IF NOT EXISTS support
                    if 'IF NOT EXISTS' in stmt:
                        conn.execute(text(stmt.replace(' IF NOT EXISTS', '')))
    except Exception:
        # Avoid crashing app startup if migration fails; rely on logs for diagnosis.
        return


def _ensure_user_columns() -> None:
    try:
        inspector = inspect(db.engine)
        if 'user' not in inspector.get_table_names():
            return

        statements = [
            'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT 1',
        ]

        with db.engine.begin() as conn:
            for stmt in statements:
                try:
                    conn.execute(text(stmt))
                except Exception:
                    if 'IF NOT EXISTS' in stmt:
                        conn.execute(text(stmt.replace(' IF NOT EXISTS', '')))
    except Exception:
        return


def _is_subcontract_bill_schema_ready() -> bool:
    try:
        inspector = inspect(db.engine)
        if 'subcontract_bill' not in inspector.get_table_names():
            return False
        existing = {c['name'] for c in inspector.get_columns('subcontract_bill')}
        required = {'period_start', 'period_end', 'due_date', 'use_hours', 'hours', 'taxable', 'hours_by_date'}
        return required.issubset(existing)
    except Exception:
        return False


with app.app_context():
    _ensure_subcontract_bill_columns()
    _ensure_user_columns()


@app.after_request
def _no_cache_dynamic_pages(response):
    """Avoid stale HTML pages after writes in hosted environments.

    Leave static assets cacheable.
    """
    try:
        if request.path.startswith('/static/'):
            return response
    except Exception:
        return response

    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


def _bootstrap_admin_credentials() -> tuple[str, str]:
    """Return bootstrap admin credentials from env.

    Supported:
    - APP_USERNAME + APP_PASSWORD
    - defaults to admin/admin for local dev
    """
    username = (os.environ.get('APP_USERNAME') or 'admin').strip() or 'admin'
    password = (os.environ.get('APP_PASSWORD') or 'admin').strip() or 'admin'
    return username, password


def _update_env_file(updates: dict[str, str]) -> None:
    """Update (or create) .env file in project root with the provided key/value pairs."""
    env_path = os.path.join(base_dir, '.env')
    existing_lines: list[str] = []
    try:
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                existing_lines = f.read().splitlines()
    except Exception:
        existing_lines = []

    seen: set[str] = set()
    out: list[str] = []
    for line in existing_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or '=' not in stripped:
            out.append(line)
            continue
        key, _ = stripped.split('=', 1)
        key = key.strip()
        if key in updates:
            value = updates[key]
            out.append(f"{key}={value}")
            seen.add(key)
        else:
            out.append(line)

    for key, value in updates.items():
        if key not in seen:
            out.append(f"{key}={value}")

    with open(env_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(out).rstrip() + '\n')


def _request_full_path() -> str:
    """Return request.full_path without a trailing '?' when no query string."""
    try:
        full_path = request.full_path or '/'
        if full_path.endswith('?'):
            return full_path[:-1]
        return full_path
    except Exception:
        return '/'


def _sanitize_next_url(next_url: str, default: str = '/') -> str:
    """Allow only local redirect targets.

    Prevents open redirects like: /login?next=https://evil.com
    """
    candidate = (next_url or '').strip()
    if not candidate:
        return default

    try:
        parts = urlsplit(candidate)
        if parts.scheme or parts.netloc:
            return default
        if not (parts.path or '').startswith('/'):
            return default
        return candidate
    except Exception:
        return default


def _is_obvious_secret_probe(path: str) -> bool:
    """Return True for paths that are almost certainly credential/config probes.

    Keep this conservative to avoid blocking real app routes.
    """
    p = (path or '').strip().lower()
    if not p:
        return False

    # Allow the standard well-known path (ACME challenges, etc.)
    if p.startswith('/.well-known/'):
        return False

    sensitive_prefixes = (
        '/.git',
        '/.aws',
        '/.docker',
        '/.terraform',
    )
    if p.startswith(sensitive_prefixes):
        return True

    sensitive_exact = {
        '/.env',
        '/.env.local',
        '/.env.production',
        '/.env.development',
        '/.env.staging',
        '/.env.example',
        '/terraform.tfstate',
        '/terraform.tfstate.backup',
        '/docker-compose.yml',
        '/docker-compose.yaml',
        '/dockerfile',
        '/phpinfo.php',
    }
    return p in sensitive_exact


def is_logged_in() -> bool:
    return bool(session.get('user_id'))


def current_user() -> User | None:
    user_id = session.get('user_id')
    if not user_id:
        return None
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None


def _is_admin_session() -> bool:
    return (session.get('role') or '') == 'admin'


def _is_owner_session() -> bool:
    return (session.get('role') or '') == 'owner'


def require_admin(view_func):
    @wraps(view_func)
    def _wrapped(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for('login', next=_request_full_path()))
        if not _is_admin_session():
            abort(403)
        return view_func(*args, **kwargs)
    return _wrapped


def require_login(view_func):
    @wraps(view_func)
    def _wrapped(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for('login', next=_request_full_path()))
        return view_func(*args, **kwargs)
    return _wrapped


@app.before_request
def _require_login():
    # Allow login page and static assets without authentication.
    if request.endpoint in {'login', 'static'}:
        return None
    # Drop obvious secret-probe requests early.
    if _is_obvious_secret_probe(request.path):
        abort(404)
    # If no route matched, let Flask return a real 404 (do not redirect to login).
    if request.endpoint is None:
        return None
    if request.path.startswith('/static/'):
        return None
    if not is_logged_in():
        return redirect(url_for('login', next=_request_full_path()))
    return None


@app.route('/login', methods=['GET', 'POST'])
def login():
    next_url = _sanitize_next_url(request.args.get('next') or '/', default='/')
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = (request.form.get('password') or '').strip()

        user = User.query.filter(func.lower(User.username) == username.lower()).first()
        if user and user.check_password(password):
            if hasattr(user, 'is_active') and user.is_active is False:
                flash('Account is on hold. Contact admin.', 'danger')
                return render_template('login.html', next_url=next_url)
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['company_id'] = user.company_id
            flash('Logged in.', 'success')
            return redirect(next_url)

        flash('Invalid username or password.', 'danger')
        return render_template('login.html', next_url=next_url)

    return render_template('login.html', next_url=next_url)


@app.route('/logout', methods=['GET'])
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('company_id', None)
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    # Protected by before_request
    if request.method == 'POST':
        current_password = (request.form.get('current_password') or '').strip()
        new_password = (request.form.get('new_password') or '').strip()
        confirm_password = (request.form.get('confirm_password') or '').strip()

        user = current_user()
        if not user:
            return redirect(url_for('login'))

        if not user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html')

        if not new_password:
            flash('New password is required.', 'danger')
            return render_template('change_password.html')

        if new_password != confirm_password:
            flash('New password and confirmation do not match.', 'danger')
            return render_template('change_password.html')

        user.set_password(new_password)
        db.session.commit()

        flash('Password updated.', 'success')
        return redirect(url_for('index'))

    return render_template('change_password.html')


@app.template_filter('money')
def money_filter(value):
    try:
        return f"${float(value):,.2f}"
    except Exception:
        return "$0.00"

# Ensure tables are created at startup
with app.app_context():
    # Safe diagnostics (does not log secrets)
    try:
        app.logger.info('DATABASE_URL set: %s', bool((os.environ.get('DATABASE_URL') or '').strip()))
    except Exception:
        pass

    db.create_all()

    try:
        app.logger.info('DB dialect: %s', getattr(db.engine.dialect, 'name', 'unknown'))
    except Exception:
        pass

    # Ensure there is always at least one admin user (bootstrap from env)
    #
    # If you ever get locked out in production, you can force-reset the admin
    # credentials by setting:
    #   FORCE_BOOTSTRAP_ADMIN=1
    #   APP_USERNAME=<admin username>
    #   APP_PASSWORD=<admin password>   (or APP_PASSWORD_HASH)
    # Then redeploy once, log in, and remove FORCE_BOOTSTRAP_ADMIN.
    try:
        force_bootstrap = (os.environ.get('FORCE_BOOTSTRAP_ADMIN') or '').strip().lower() in {'1', 'true', 'yes', 'on'}
        admin_username = (os.environ.get('APP_USERNAME') or 'admin').strip() or 'admin'
        password_hash = (os.environ.get('APP_PASSWORD_HASH') or '').strip()
        _, admin_password = _bootstrap_admin_credentials()

        # Any existing admin (used to decide whether we must create one).
        any_admin = User.query.filter(User.role == 'admin').first()

        # Any user matching APP_USERNAME (admin or owner).
        target_user = User.query.filter(func.lower(User.username) == admin_username.lower()).first()

        if not any_admin:
            # Fresh DB: create the first admin user.
            u = User(username=admin_username, role='admin', company_id=None)
            if password_hash:
                u.password_hash = password_hash
            else:
                u.set_password(admin_password)
            db.session.add(u)
            db.session.commit()
        elif force_bootstrap:
            # Operator recovery mode: ensure APP_USERNAME exists and is admin.
            if not target_user:
                target_user = User(username=admin_username, role='admin', company_id=None)
                db.session.add(target_user)

            # Promote to admin and detach from any company scope.
            target_user.role = 'admin'
            target_user.company_id = None

            # Reset password.
            if password_hash:
                target_user.password_hash = password_hash
            else:
                target_user.set_password(admin_password)

            db.session.commit()
    except Exception:
        db.session.rollback()

    # Lightweight migration for existing SQLite DBs (add missing columns)
    # IMPORTANT: PRAGMA/ALTER TABLE statements below are SQLite-only.
    is_sqlite = False
    try:
        is_sqlite = (db.engine.dialect.name == 'sqlite')
    except Exception:
        is_sqlite = False

    if is_sqlite:
        try:
            existing_cols = {
                row[1]
                for row in db.session.execute(db.text("PRAGMA table_info('payroll_line')")).fetchall()
            }
            if 'hours' not in existing_cols:
                db.session.execute(db.text('ALTER TABLE payroll_line ADD COLUMN hours FLOAT DEFAULT 0'))
            if 'vacation_pay' not in existing_cols:
                db.session.execute(db.text('ALTER TABLE payroll_line ADD COLUMN vacation_pay FLOAT DEFAULT 0'))
            if 'cpp2_employee' not in existing_cols:
                db.session.execute(db.text('ALTER TABLE payroll_line ADD COLUMN cpp2_employee FLOAT DEFAULT 0'))
            if 'cpp2_employer' not in existing_cols:
                db.session.execute(db.text('ALTER TABLE payroll_line ADD COLUMN cpp2_employer FLOAT DEFAULT 0'))
            db.session.commit()
        except Exception:
            db.session.rollback()

    # Lightweight migration for existing SQLite DBs: add any new tables if missing
    # (db.create_all already creates missing tables; keep this block for symmetry)

    if is_sqlite:
        try:
            existing_emp_cols = {
                row[1]
                for row in db.session.execute(db.text("PRAGMA table_info('employee')")).fetchall()
            }
            if 'vacation_pay_enabled' not in existing_emp_cols:
                db.session.execute(db.text('ALTER TABLE employee ADD COLUMN vacation_pay_enabled BOOLEAN DEFAULT 0'))
            if 'ei_exempt' not in existing_emp_cols:
                db.session.execute(db.text('ALTER TABLE employee ADD COLUMN ei_exempt BOOLEAN DEFAULT 0'))
            db.session.commit()
        except Exception:
            db.session.rollback()

        try:
            existing_sub_cols = {
                row[1]
                for row in db.session.execute(db.text("PRAGMA table_info('payroll_submission')")).fetchall()
            }
            if 'period_start' not in existing_sub_cols:
                db.session.execute(db.text('ALTER TABLE payroll_submission ADD COLUMN period_start DATE'))
            if 'period_end' not in existing_sub_cols:
                db.session.execute(db.text('ALTER TABLE payroll_submission ADD COLUMN period_end DATE'))
            db.session.commit()
        except Exception:
            db.session.rollback()


@app.route('/')
def index():
    # No dashboard metrics or payroll activity on homepage
    company_name = ''
    company_number = ''
    role_label = 'User'
    if _is_owner_session() and session.get('company_id'):
        try:
            c = db.session.get(Company, int(session.get('company_id')))
            if c and c.name:
                company_name = c.name
                company_number = c.business_number or ''
        except Exception:
            company_name = ''
    elif _is_admin_session():
        role_label = 'Admin'
    return render_template(
        'index.html',
        company_name=company_name,
        company_number=company_number,
        role_label=role_label,
    )


@app.route('/companies', methods=['GET', 'POST'])
@require_admin
def companies():
    if request.method == 'POST':
        name = request.form['name']
        if not name or not name.strip():
            flash('Company name is required.', 'danger')
            return redirect(url_for('companies'))
        address = request.form.get('address')
        bn = request.form.get('business_number')
        company = Company(name=name, address=address, business_number=bn)
        db.session.add(company)
        db.session.commit()

        owner_username = (request.form.get('owner_username') or '').strip()
        owner_password = (request.form.get('owner_password') or '').strip()
        if owner_username or owner_password:
            if not owner_username or not owner_password:
                flash('Owner username and password must both be provided (or leave both blank).', 'danger')
                return redirect(url_for('companies'))
            existing = User.query.filter(func.lower(User.username) == owner_username.lower()).first()
            if existing:
                flash('Owner username already exists. Choose another username.', 'danger')
                return redirect(url_for('companies'))
            owner_user = User(username=owner_username, role='owner', company_id=company.id)
            owner_user.set_password(owner_password)
            db.session.add(owner_user)
            db.session.commit()

        flash('Company created.', 'success')
        return redirect(url_for('companies'))
    companies = Company.query.all()
    return render_template('companies.html', companies=companies)


@app.route('/manage/companies', methods=['GET'])
@require_admin
def manage_companies():
    companies = Company.query.order_by(Company.name).all()
    company_id = (request.args.get('company_id') or '').strip()
    selected_company = None
    if company_id:
        try:
            selected_company = db.session.get(Company, int(company_id))
        except Exception:
            selected_company = None
    return render_template(
        'manage_companies.html',
        companies=companies,
        selected_company_id=company_id,
        selected_company=selected_company,
    )


@app.route('/companies/<int:company_id>/delete', methods=['POST'])
@require_admin
def delete_company(company_id):
    c = db.session.get(Company, company_id)
    if not c:
        abort(404)
    db.session.delete(c)
    db.session.commit()
    flash('Company deleted.', 'success')
    return redirect(url_for('companies'))


@app.route('/companies/<int:company_id>/edit', methods=['GET', 'POST'])
@require_admin
def edit_company(company_id):
    c = db.session.get(Company, company_id)
    if not c:
        abort(404)
    if request.method == 'POST':
        c.name = request.form.get('name')
        c.address = request.form.get('address')
        c.business_number = request.form.get('business_number')
        # handle logo upload
        logo = request.files.get('logo')
        if logo and logo.filename:
            filename = secure_filename(logo.filename)
            save_name = f"company_{c.id}_" + filename
            path = os.path.join(LOGO_FOLDER, save_name)
            logo.save(path)
            c.logo_filename = save_name
        db.session.commit()
        flash('Company updated.', 'success')
        return redirect(url_for('companies'))
    return render_template('edit_company.html', company=c)


def _allowed_company_ids_for_session() -> set[int]:
    if _is_admin_session():
        return {c.id for c in Company.query.with_entities(Company.id).all()}
    if _is_owner_session() and session.get('company_id'):
        try:
            return {int(session.get('company_id'))}
        except Exception:
            return set()
    return set()


def _require_employee_access(employee: Employee) -> None:
    if _is_admin_session():
        return
    company_id = session.get('company_id')
    if not company_id or not employee or employee.company_id != int(company_id):
        abort(403)


def _parse_date(value: str | None) -> datetime.date | None:
    if not value:
        return None
    try:
        return datetime.date.fromisoformat(value)
    except Exception:
        return None


@app.context_processor
def _inject_company_header():
    header_company_name = ''
    header_company_number = ''
    if _is_owner_session() and session.get('company_id'):
        try:
            c = db.session.get(Company, int(session.get('company_id')))
            if c:
                header_company_name = c.name or ''
                header_company_number = c.business_number or ''
        except Exception:
            header_company_name = ''
            header_company_number = ''
    return {
        'header_company_name': header_company_name,
        'header_company_number': header_company_number,
    }


@app.route('/payroll', methods=['GET'])
@require_login
def payroll_home():
    if _is_owner_session():
        return redirect(url_for('owner_payroll'))
    if _is_admin_session():
        return redirect(url_for('data_entry'))
    return redirect(url_for('employees'))


@app.route('/expenses', methods=['GET'])
@require_login
def expenses_home():
    _ensure_subcontract_bill_columns()
    schema_ready = _is_subcontract_bill_schema_ready()
    today = datetime.date.today()
    date_from = today - datetime.timedelta(days=14)

    bills = []
    if schema_ready and _is_admin_session():
        bills = (
            SubcontractBill.query
            .join(Subcontractor)
            .filter(SubcontractBill.bill_date >= date_from)
            .order_by(SubcontractBill.bill_date.desc(), SubcontractBill.id.desc())
            .limit(200)
            .all()
        )
    elif schema_ready:
        cid = session.get('company_id')
        if cid:
            bills = (
                SubcontractBill.query
                .join(Subcontractor)
                .filter(SubcontractBill.company_id == int(cid))
                .filter(SubcontractBill.bill_date >= date_from)
                .order_by(SubcontractBill.bill_date.desc(), SubcontractBill.id.desc())
                .limit(200)
                .all()
            )

    totals = {
        'amount': sum(float(b.amount or 0.0) for b in bills),
        'gst': sum(float(b.gst_amount or 0.0) for b in bills),
        'total': sum(float(b.total or 0.0) for b in bills),
    }

    return render_template(
        'expenses_home.html',
        bills=bills,
        totals=totals,
        date_from=date_from,
        date_to=today,
        schema_ready=schema_ready,
    )


@app.route('/sales', methods=['GET', 'POST'])
@require_login
def sales_home():
    if _is_admin_session():
        companies = Company.query.order_by(Company.name).all()
    else:
        cid = session.get('company_id')
        companies = Company.query.filter(Company.id == int(cid)).order_by(Company.name).all() if cid else []

    selected_company_id = (request.values.get('company_id') or '').strip()
    if _is_owner_session():
        selected_company_id = str(session.get('company_id') or '').strip()

    customers = []
    invoices = []
    if selected_company_id:
        try:
            company_id_int = int(selected_company_id)
        except Exception:
            company_id_int = None
        else:
            customers = (
                Customer.query
                .filter(Customer.company_id == company_id_int)
                .order_by(Customer.name.asc())
                .all()
            )
            invoices = (
                SalesInvoice.query
                .filter(SalesInvoice.company_id == company_id_int)
                .order_by(SalesInvoice.created_at.desc(), SalesInvoice.id.desc())
                .limit(50)
                .all()
            )

    if request.method == 'POST':
        form_type = (request.form.get('form_type') or '').strip()
        if form_type == 'customer':
            company_id_raw = (request.form.get('company_id') or '').strip()
            name = (request.form.get('customer_name') or '').strip()
            company_name = (request.form.get('customer_company') or '').strip()
            email = (request.form.get('customer_email') or '').strip()
            phone = (request.form.get('customer_phone') or '').strip()
            address = (request.form.get('customer_address') or '').strip()
            tax_number = (request.form.get('customer_tax') or '').strip()

            if _is_owner_session():
                company_id_raw = str(session.get('company_id') or '').strip()

            if not company_id_raw:
                flash('Company is required.', 'danger')
                return redirect(url_for('sales_home'))
            if not name:
                flash('Customer name is required.', 'danger')
                return redirect(url_for('sales_home', company_id=company_id_raw))

            try:
                company_id_int = int(company_id_raw)
            except Exception:
                flash('Company selection is invalid.', 'danger')
                return redirect(url_for('sales_home'))

            allowed_company_ids = _allowed_company_ids_for_session()
            if company_id_int not in allowed_company_ids:
                abort(403)

            customer = Customer(
                company_id=company_id_int,
                name=name,
                company_name=company_name or None,
                email=email or None,
                phone=phone or None,
                address=address or None,
                tax_number=tax_number or None,
            )
            db.session.add(customer)
            db.session.commit()
            flash('Customer saved.', 'success')
            return redirect(url_for('sales_home', company_id=company_id_int, view='customers'))

        if form_type == 'invoice':
            company_id_raw = (request.form.get('company_id') or '').strip()
            customer_id_raw = (request.form.get('customer_id') or '').strip()
            invoice_date_raw = (request.form.get('invoice_date') or '').strip()
            due_date_raw = (request.form.get('due_date') or '').strip()
            terms = (request.form.get('terms') or '').strip()
            message = (request.form.get('message') or '').strip()
            statement_message = (request.form.get('statement_message') or '').strip()
            lines_raw = (request.form.get('invoice_lines_json') or '').strip()

            if _is_owner_session():
                company_id_raw = str(session.get('company_id') or '').strip()

            if not company_id_raw:
                flash('Company is required.', 'danger')
                return redirect(url_for('sales_home'))
            if not customer_id_raw:
                flash('Customer is required.', 'danger')
                return redirect(url_for('sales_home', company_id=company_id_raw))

            try:
                company_id_int = int(company_id_raw)
            except Exception:
                flash('Company selection is invalid.', 'danger')
                return redirect(url_for('sales_home'))

            allowed_company_ids = _allowed_company_ids_for_session()
            if company_id_int not in allowed_company_ids:
                abort(403)

            try:
                customer_id_int = int(customer_id_raw)
            except Exception:
                flash('Customer selection is invalid.', 'danger')
                return redirect(url_for('sales_home', company_id=company_id_raw))

            customer = db.session.get(Customer, customer_id_int)
            if not customer or int(customer.company_id or 0) != company_id_int:
                flash('Customer does not belong to this company.', 'danger')
                return redirect(url_for('sales_home', company_id=company_id_raw))

            invoice_date = _parse_date(invoice_date_raw)
            if not invoice_date:
                flash('Invoice date is required.', 'danger')
                return redirect(url_for('sales_home', company_id=company_id_raw))

            due_date = _parse_date(due_date_raw) if due_date_raw else None
            if due_date_raw and not due_date:
                flash('Due date must be valid.', 'danger')
                return redirect(url_for('sales_home', company_id=company_id_raw))

            try:
                lines = json.loads(lines_raw) if lines_raw else []
            except Exception:
                lines = []

            if not lines:
                flash('Add at least one invoice line.', 'danger')
                return redirect(url_for('sales_home', company_id=company_id_raw))

            subtotal = 0.0
            tax_total = 0.0
            total = 0.0
            invoice = SalesInvoice(
                company_id=company_id_int,
                customer_id=customer_id_int,
                invoice_date=invoice_date,
                due_date=due_date,
                terms=terms or None,
                message=message or None,
                statement_message=statement_message or None,
            )
            db.session.add(invoice)
            db.session.flush()

            for line in lines:
                service = (line.get('service') or '').strip()
                description = (line.get('description') or '').strip()
                try:
                    qty = float(line.get('qty') or 0)
                except Exception:
                    qty = 0.0
                try:
                    rate = float(line.get('rate') or 0)
                except Exception:
                    rate = 0.0
                taxable = bool(line.get('taxable'))
                amount = qty * rate
                tax_amount = amount * 0.13 if taxable else 0.0
                line_total = amount + tax_amount

                subtotal += amount
                tax_total += tax_amount
                total += line_total

                db.session.add(SalesInvoiceLine(
                    invoice_id=invoice.id,
                    service=service or None,
                    description=description or None,
                    qty=qty,
                    rate=rate,
                    taxable=taxable,
                    amount=amount,
                    tax_amount=tax_amount,
                    total=line_total,
                ))

            invoice.subtotal = subtotal
            invoice.tax_total = tax_total
            invoice.total = total
            invoice.balance_due = total
            db.session.commit()
            flash('Invoice saved.', 'success')
            return redirect(url_for('sales_home', company_id=company_id_int, invoice_id=invoice.id))

    selected_invoice_id = (request.args.get('invoice_id') or '').strip()
    saved_invoice = None
    if selected_invoice_id.isdigit():
        try:
            candidate = db.session.get(SalesInvoice, int(selected_invoice_id))
        except Exception:
            candidate = None
        if candidate:
            if _is_admin_session() or int(candidate.company_id or 0) == int(session.get('company_id') or 0):
                saved_invoice = candidate

    show_customers = (request.args.get('view') or '').strip() == 'customers'

    return render_template(
        'sales_home.html',
        companies=companies,
        customers=customers,
        invoices=invoices,
        selected_company_id=selected_company_id,
        saved_invoice=saved_invoice,
        show_customers=show_customers,
    )


@app.route('/sales/customers/<int:customer_id>/edit', methods=['GET', 'POST'])
@require_login
def sales_customer_edit(customer_id: int):
    customer = db.session.get(Customer, customer_id)
    if not customer:
        abort(404)

    allowed_company_ids = _allowed_company_ids_for_session()
    if int(customer.company_id or 0) not in allowed_company_ids:
        abort(403)

    if request.method == 'POST':
        name = (request.form.get('customer_name') or '').strip()
        company_name = (request.form.get('customer_company') or '').strip()
        email = (request.form.get('customer_email') or '').strip()
        phone = (request.form.get('customer_phone') or '').strip()
        address = (request.form.get('customer_address') or '').strip()
        tax_number = (request.form.get('customer_tax') or '').strip()

        if not name:
            flash('Customer name is required.', 'danger')
            return redirect(url_for('sales_customer_edit', customer_id=customer_id))

        customer.name = name
        customer.company_name = company_name or None
        customer.email = email or None
        customer.phone = phone or None
        customer.address = address or None
        customer.tax_number = tax_number or None
        db.session.commit()
        flash('Customer updated.', 'success')
        return redirect(url_for('sales_home', company_id=customer.company_id))

    return render_template('edit_customer.html', customer=customer)


@app.route('/sales/invoices/<int:invoice_id>/edit', methods=['GET', 'POST'])
@require_login
def sales_invoice_edit(invoice_id: int):
    invoice = db.session.get(SalesInvoice, invoice_id)
    if not invoice:
        abort(404)

    allowed_company_ids = _allowed_company_ids_for_session()
    if int(invoice.company_id or 0) not in allowed_company_ids:
        abort(403)

    customers = (
        Customer.query
        .filter(Customer.company_id == int(invoice.company_id))
        .order_by(Customer.name.asc())
        .all()
    )

    if request.method == 'POST':
        customer_id_raw = (request.form.get('customer_id') or '').strip()
        invoice_date_raw = (request.form.get('invoice_date') or '').strip()
        due_date_raw = (request.form.get('due_date') or '').strip()
        terms = (request.form.get('terms') or '').strip()
        message = (request.form.get('message') or '').strip()
        statement_message = (request.form.get('statement_message') or '').strip()
        lines_raw = (request.form.get('invoice_lines_json') or '').strip()

        if not customer_id_raw:
            flash('Customer is required.', 'danger')
            return redirect(url_for('sales_invoice_edit', invoice_id=invoice_id))

        try:
            customer_id_int = int(customer_id_raw)
        except Exception:
            flash('Customer selection is invalid.', 'danger')
            return redirect(url_for('sales_invoice_edit', invoice_id=invoice_id))

        customer = db.session.get(Customer, customer_id_int)
        if not customer or int(customer.company_id or 0) != int(invoice.company_id or 0):
            flash('Customer does not belong to this company.', 'danger')
            return redirect(url_for('sales_invoice_edit', invoice_id=invoice_id))

        invoice_date = _parse_date(invoice_date_raw)
        if not invoice_date:
            flash('Invoice date is required.', 'danger')
            return redirect(url_for('sales_invoice_edit', invoice_id=invoice_id))

        due_date = _parse_date(due_date_raw) if due_date_raw else None
        if due_date_raw and not due_date:
            flash('Due date must be valid.', 'danger')
            return redirect(url_for('sales_invoice_edit', invoice_id=invoice_id))

        try:
            lines = json.loads(lines_raw) if lines_raw else []
        except Exception:
            lines = []

        if not lines:
            flash('Add at least one invoice line.', 'danger')
            return redirect(url_for('sales_invoice_edit', invoice_id=invoice_id))

        subtotal = 0.0
        tax_total = 0.0
        total = 0.0

        invoice.customer_id = customer_id_int
        invoice.invoice_date = invoice_date
        invoice.due_date = due_date
        invoice.terms = terms or None
        invoice.message = message or None
        invoice.statement_message = statement_message or None

        SalesInvoiceLine.query.filter(SalesInvoiceLine.invoice_id == invoice.id).delete()

        for line in lines:
            service = (line.get('service') or '').strip()
            description = (line.get('description') or '').strip()
            try:
                qty = float(line.get('qty') or 0)
            except Exception:
                qty = 0.0
            try:
                rate = float(line.get('rate') or 0)
            except Exception:
                rate = 0.0
            taxable = bool(line.get('taxable'))
            amount = qty * rate
            tax_amount = amount * 0.13 if taxable else 0.0
            line_total = amount + tax_amount

            subtotal += amount
            tax_total += tax_amount
            total += line_total

            db.session.add(SalesInvoiceLine(
                invoice_id=invoice.id,
                service=service or None,
                description=description or None,
                qty=qty,
                rate=rate,
                taxable=taxable,
                amount=amount,
                tax_amount=tax_amount,
                total=line_total,
            ))

        invoice.subtotal = subtotal
        invoice.tax_total = tax_total
        invoice.total = total
        invoice.balance_due = total
        db.session.commit()
        flash('Invoice updated.', 'success')
        return redirect(url_for('sales_home', company_id=invoice.company_id, invoice_id=invoice.id))

    lines_data = [
        {
            'service': line.service or '',
            'description': line.description or '',
            'qty': float(line.qty or 0.0),
            'rate': float(line.rate or 0.0),
            'taxable': bool(line.taxable),
        }
        for line in invoice.lines
    ]

    return render_template(
        'edit_invoice.html',
        invoice=invoice,
        customers=customers,
        lines_data=lines_data,
    )


@app.route('/sales/invoices/<int:invoice_id>/print', methods=['GET'])
@require_login
def sales_invoice_print(invoice_id: int):
    invoice = db.session.get(SalesInvoice, invoice_id)
    if not invoice:
        abort(404)

    if not _is_admin_session():
        cid = session.get('company_id')
        if not cid or int(cid) != int(invoice.company_id or 0):
            abort(403)

    return render_template('sales_invoice_print.html', invoice=invoice)


@app.route('/sales/reports', methods=['GET'])
@require_login
def sales_reports():
    if _is_admin_session():
        companies = Company.query.order_by(Company.name).all()
    else:
        cid = session.get('company_id')
        companies = Company.query.filter(Company.id == int(cid)).order_by(Company.name).all() if cid else []

    company_id = (request.args.get('company_id') or '').strip()
    customer_id = (request.args.get('customer_id') or '').strip()
    date_from = (request.args.get('date_from') or '').strip()
    date_to = (request.args.get('date_to') or '').strip()
    run = (request.args.get('run') or '').strip()

    if _is_owner_session():
        company_id = str(session.get('company_id') or '').strip()

    customers = []
    require_company_filter = False
    if company_id:
        try:
            company_id_int = int(company_id)
        except Exception:
            company_id_int = None
        else:
            customers = (
                Customer.query
                .filter(Customer.company_id == company_id_int)
                .order_by(Customer.name.asc())
                .all()
            )
    else:
        if _is_admin_session():
            require_company_filter = True

    invoices = []
    totals = {'subtotal': 0.0, 'tax': 0.0, 'total': 0.0}
    if run == '1':
        if _is_admin_session() and not company_id:
            require_company_filter = True
        else:
            q = SalesInvoice.query
            if company_id:
                q = q.filter(SalesInvoice.company_id == int(company_id))
            if customer_id:
                q = q.filter(SalesInvoice.customer_id == int(customer_id))
            if date_from:
                q = q.filter(SalesInvoice.invoice_date >= date_from)
            if date_to:
                q = q.filter(SalesInvoice.invoice_date <= date_to)
            invoices = q.order_by(SalesInvoice.invoice_date.desc(), SalesInvoice.id.desc()).all()
            for inv in invoices:
                totals['subtotal'] += float(inv.subtotal or 0.0)
                totals['tax'] += float(inv.tax_total or 0.0)
                totals['total'] += float(inv.total or 0.0)

    return render_template(
        'sales_reports.html',
        companies=companies,
        customers=customers,
        invoices=invoices,
        totals=totals,
        selected_company_id=company_id,
        selected_customer_id=customer_id,
        selected_date_from=date_from,
        selected_date_to=date_to,
        run=run,
        require_company_filter=require_company_filter,
    )


@app.route('/employees', methods=['GET', 'POST'])
@require_login
def employees():
    if _is_admin_session():
        companies = Company.query.all()
    else:
        cid = session.get('company_id')
        companies = Company.query.filter(Company.id == int(cid)).all() if cid else []
    if request.method == 'POST':
        worker_type = (request.form.get('worker_type') or 'employee').strip().lower()
        if worker_type == 'subcontract':
            company_id_raw = (request.form.get('company_id') or '').strip()
            contractor_company_name = (request.form.get('contractor_company_name') or '').strip()
            address = (request.form.get('contractor_address') or '').strip()
            tax_number = (request.form.get('tax_number') or '').strip()
            contract_rate_raw = (request.form.get('contract_rate') or '').strip()

            if _is_owner_session():
                company_id_raw = str(session.get('company_id') or '').strip()

            if not company_id_raw:
                flash('Company is required.', 'danger')
                return redirect(url_for('employees'))
            if not contractor_company_name:
                flash('Sub-contract company name is required.', 'danger')
                return redirect(url_for('employees'))
            if not address:
                flash('Address is required.', 'danger')
                return redirect(url_for('employees'))
            if not contract_rate_raw:
                flash('Contract rate is required.', 'danger')
                return redirect(url_for('employees'))

            try:
                company_id = int(company_id_raw)
            except Exception:
                flash('Company selection is invalid.', 'danger')
                return redirect(url_for('employees'))

            allowed_company_ids = _allowed_company_ids_for_session()
            if company_id not in allowed_company_ids:
                abort(403)

            if not db.session.get(Company, company_id):
                flash('Selected company does not exist.', 'danger')
                return redirect(url_for('employees'))

            try:
                contract_rate = float(contract_rate_raw)
            except Exception:
                flash('Contract rate must be a number.', 'danger')
                return redirect(url_for('employees'))

            if contract_rate < 0:
                flash('Contract rate cannot be negative.', 'danger')
                return redirect(url_for('employees'))

            sub = Subcontractor(
                company_id=company_id,
                contractor_company_name=contractor_company_name,
                address=address,
                tax_number=tax_number,
                gst_rate=0.13,
                contract_rate=contract_rate,
            )
            db.session.add(sub)
            db.session.commit()
            flash('Sub-contract added.', 'success')
            return redirect(url_for('employees'))

        # Accept a single Name field on the form and store it in first_name
        # (keep last_name blank for compatibility with existing model/templates)
        name = (request.form.get('name') or '').strip()
        address = (request.form.get('address') or '').strip()
        sin = (request.form.get('sin') or '').strip()
        hire_date_raw = (request.form.get('hire_date') or '').strip()
        payroll_frequency = (request.form.get('payroll_frequency') or '').strip()
        pay_rate_raw = (request.form.get('pay_rate') or '').strip()
        company_id_raw = (request.form.get('company_id') or '').strip()
        vacation_pay_raw = (request.form.get('vacation_pay') or '').strip().lower()
        ei_exempt_raw = (request.form.get('ei_exempt') or '').strip().lower()

        if not name:
            flash('Name is required.', 'danger')
            return redirect(url_for('employees'))
        if _is_owner_session():
            company_id_raw = str(session.get('company_id') or '').strip()
        if not company_id_raw:
            flash('Company is required.', 'danger')
            return redirect(url_for('employees'))
        if not address:
            flash('Address is required.', 'danger')
            return redirect(url_for('employees'))
        if not sin:
            flash('SIN is required.', 'danger')
            return redirect(url_for('employees'))
        if not hire_date_raw:
            flash('Hire date is required.', 'danger')
            return redirect(url_for('employees'))
        if not payroll_frequency:
            flash('Payroll frequency is required.', 'danger')
            return redirect(url_for('employees'))
        if not pay_rate_raw:
            flash('Pay rate is required.', 'danger')
            return redirect(url_for('employees'))

        try:
            hire_date = datetime.date.fromisoformat(hire_date_raw)
        except Exception:
            flash('Hire date must be a valid date.', 'danger')
            return redirect(url_for('employees'))

        try:
            pay_rate = float(pay_rate_raw)
        except Exception:
            flash('Pay rate must be a number.', 'danger')
            return redirect(url_for('employees'))

        try:
            company_id = int(company_id_raw)
        except Exception:
            flash('Company selection is invalid.', 'danger')
            return redirect(url_for('employees'))

        allowed_company_ids = _allowed_company_ids_for_session()
        if company_id not in allowed_company_ids:
            abort(403)

        if not db.session.get(Company, company_id):
            flash('Selected company does not exist.', 'danger')
            return redirect(url_for('employees'))

        vacation_pay_enabled = vacation_pay_raw in {'yes', '1', 'true', 'on'}
        ei_exempt = ei_exempt_raw in {'yes', '1', 'true', 'on'}

        emp = Employee(
            first_name=name,
            last_name='',
            address=address,
            sin=sin,
            hire_date=hire_date,
            payroll_frequency=payroll_frequency,
            pay_rate=pay_rate,
            vacation_pay_enabled=vacation_pay_enabled,
            ei_exempt=ei_exempt,
            company_id=company_id,
            annual_salary=0,
        )
        db.session.add(emp)
        db.session.commit()
        flash('Employee added.', 'success')
        return redirect(url_for('employees'))
    return render_template('employees.html', companies=companies)


@app.route('/manage/employees', methods=['GET'])
@require_login
def manage_employees():
    if _is_admin_session():
        companies = Company.query.order_by(Company.name).all()
    else:
        cid = session.get('company_id')
        companies = Company.query.filter(Company.id == int(cid)).order_by(Company.name).all() if cid else []

    run = (request.args.get('run') or '').strip()
    company_id = (request.args.get('company_id') or '').strip()
    employee_id = (request.args.get('employee_id') or '').strip()

    if _is_owner_session():
        company_id = str(session.get('company_id') or '').strip()

    require_company_filter = False
    if _is_admin_session() and not company_id:
        employees_for_dropdown = []
        require_company_filter = True
    else:
        employees_for_dropdown = Employee.query
        if company_id:
            try:
                employees_for_dropdown = employees_for_dropdown.filter(Employee.company_id == int(company_id))
            except Exception:
                employees_for_dropdown = employees_for_dropdown
        employees_for_dropdown = employees_for_dropdown.order_by(Employee.first_name, Employee.last_name).all()

    employees = []
    if run == '1':
        if _is_admin_session() and not company_id:
            require_company_filter = True
        else:
            q = Employee.query
            if company_id:
                q = q.filter(Employee.company_id == int(company_id))
            if employee_id:
                q = q.filter(Employee.id == int(employee_id))
            employees = q.order_by(Employee.first_name, Employee.last_name).all()

    return render_template(
        'manage_employees.html',
        companies=companies,
        employees_for_dropdown=employees_for_dropdown,
        employees=employees,
        selected_company_id=company_id,
        selected_employee_id=employee_id,
        run=run,
        require_company_filter=require_company_filter,
    )


@app.route('/manage/subcontracts', methods=['GET'])
@require_login
def manage_subcontracts():
    if _is_admin_session():
        companies = Company.query.order_by(Company.name).all()
    else:
        cid = session.get('company_id')
        companies = Company.query.filter(Company.id == int(cid)).order_by(Company.name).all() if cid else []

    run = (request.args.get('run') or '').strip()
    company_id = (request.args.get('company_id') or '').strip()

    if _is_owner_session():
        company_id = str(session.get('company_id') or '').strip()

    subs = []
    require_company_filter = False
    if run == '1':
        if _is_admin_session() and not company_id:
            require_company_filter = True
        else:
            q = Subcontractor.query
            if company_id:
                q = q.filter(Subcontractor.company_id == int(company_id))
            subs = q.order_by(Subcontractor.contractor_company_name.asc(), Subcontractor.id.asc()).all()

    return render_template(
        'manage_subcontracts.html',
        companies=companies,
        subcontractors=subs,
        selected_company_id=company_id,
        run=run,
        require_company_filter=require_company_filter,
    )


@app.route('/subcontracts/new', methods=['GET', 'POST'])
@require_login
def new_subcontractor():
    if _is_admin_session():
        companies = Company.query.order_by(Company.name).all()
    else:
        cid = session.get('company_id')
        companies = Company.query.filter(Company.id == int(cid)).order_by(Company.name).all() if cid else []

    selected_company_id = (request.args.get('company_id') or '').strip()
    if _is_owner_session():
        selected_company_id = str(session.get('company_id') or '').strip()

    if request.method == 'POST':
        company_id_raw = (request.form.get('company_id') or '').strip()
        contractor_company_name = (request.form.get('contractor_company_name') or '').strip()
        address = (request.form.get('contractor_address') or '').strip()
        tax_number = (request.form.get('tax_number') or '').strip()
        contract_rate_raw = (request.form.get('contract_rate') or '').strip()

        if _is_owner_session():
            company_id_raw = str(session.get('company_id') or '').strip()

        if not company_id_raw:
            flash('Company is required.', 'danger')
            return redirect(url_for('new_subcontractor', company_id=selected_company_id))
        if not contractor_company_name:
            flash('Sub-contract company name is required.', 'danger')
            return redirect(url_for('new_subcontractor', company_id=company_id_raw))
        if not address:
            flash('Address is required.', 'danger')
            return redirect(url_for('new_subcontractor', company_id=company_id_raw))
        if not contract_rate_raw:
            flash('Contract rate is required.', 'danger')
            return redirect(url_for('new_subcontractor', company_id=company_id_raw))

        try:
            company_id = int(company_id_raw)
        except Exception:
            flash('Company selection is invalid.', 'danger')
            return redirect(url_for('new_subcontractor', company_id=company_id_raw))

        allowed_company_ids = _allowed_company_ids_for_session()
        if company_id not in allowed_company_ids:
            abort(403)

        if not db.session.get(Company, company_id):
            flash('Selected company does not exist.', 'danger')
            return redirect(url_for('new_subcontractor', company_id=company_id_raw))

        try:
            contract_rate = float(contract_rate_raw)
        except Exception:
            flash('Contract rate must be a number.', 'danger')
            return redirect(url_for('new_subcontractor', company_id=company_id_raw))

        if contract_rate < 0:
            flash('Contract rate cannot be negative.', 'danger')
            return redirect(url_for('new_subcontractor', company_id=company_id_raw))

        sub = Subcontractor(
            company_id=company_id,
            contractor_company_name=contractor_company_name,
            address=address,
            tax_number=tax_number,
            gst_rate=0.13,
            contract_rate=contract_rate,
        )
        db.session.add(sub)
        db.session.commit()
        flash('Supplier added.', 'success')
        return redirect(url_for('new_subcontractor', company_id=company_id))

    require_company_filter = False
    if _is_admin_session() and not selected_company_id:
        subcontractors = []
        require_company_filter = True
    else:
        subs_query = Subcontractor.query
        if selected_company_id:
            try:
                subs_query = subs_query.filter(Subcontractor.company_id == int(selected_company_id))
            except Exception:
                subs_query = subs_query
        elif _is_owner_session():
            subs_query = subs_query.filter(Subcontractor.company_id == int(session.get('company_id') or 0))

        subcontractors = subs_query.order_by(Subcontractor.contractor_company_name.asc(), Subcontractor.id.asc()).all()

    return render_template(
        'subcontract_new.html',
        companies=companies,
        subcontractors=subcontractors,
        selected_company_id=selected_company_id,
        require_company_filter=require_company_filter,
    )


@app.route('/subcontracts/bills', methods=['GET', 'POST'])
@require_login
def subcontract_bills():
    _ensure_subcontract_bill_columns()
    schema_ready = _is_subcontract_bill_schema_ready()
    if _is_admin_session():
        companies = Company.query.order_by(Company.name).all()
    else:
        cid = session.get('company_id')
        companies = Company.query.filter(Company.id == int(cid)).order_by(Company.name).all() if cid else []

    run = (request.args.get('run') or '').strip()
    company_id = (request.values.get('company_id') or '').strip()
    subcontractor_id = (request.values.get('subcontractor_id') or '').strip()
    date_from = (request.values.get('date_from') or '').strip()
    date_to = (request.values.get('date_to') or '').strip()

    if _is_owner_session():
        company_id = str(session.get('company_id') or '').strip()

    allowed_company_ids = _allowed_company_ids_for_session()
    company_id_int = None
    if company_id:
        try:
            company_id_int = int(company_id)
        except Exception:
            company_id_int = None
        if company_id_int is not None and company_id_int not in allowed_company_ids:
            abort(403)

    subs_query = Subcontractor.query
    if company_id_int is not None:
        subs_query = subs_query.filter(Subcontractor.company_id == company_id_int)
    elif not _is_admin_session():
        subs_query = subs_query.filter(Subcontractor.company_id == -1)

    subcontractors = subs_query.order_by(Subcontractor.contractor_company_name.asc()).all()

    if request.method == 'POST':
        if not schema_ready:
            flash('Bills schema is updating. Run the migration and retry.', 'danger')
            return redirect(url_for('subcontract_bills'))
        bill_date_raw = (request.form.get('bill_date') or '').strip()
        period_start_raw = (request.form.get('period_start') or '').strip()
        period_end_raw = (request.form.get('period_end') or '').strip()
        due_date_raw = (request.form.get('due_date') or '').strip()
        amount_raw = (request.form.get('amount') or '').strip()
        hours_raw = (request.form.get('hours') or '').strip()
        description = (request.form.get('description') or '').strip()
        sub_id_raw = (request.form.get('subcontractor_id') or '').strip()
        use_hours = (request.form.get('use_hours') or '').strip().lower() in {'1', 'true', 'on', 'yes'}
        taxable = (request.form.get('taxable') or '').strip().lower() in {'1', 'true', 'on', 'yes'}

        if not company_id:
            flash('Company is required.', 'danger')
            return redirect(url_for('subcontract_bills'))
        if not sub_id_raw:
            flash('Supplier is required.', 'danger')
            return redirect(url_for('subcontract_bills', company_id=company_id))

        bill_date = _parse_date(bill_date_raw)
        if not bill_date:
            flash('Bill date is required.', 'danger')
            return redirect(url_for('subcontract_bills', company_id=company_id, subcontractor_id=sub_id_raw))

        period_start = _parse_date(period_start_raw) if period_start_raw else None
        period_end = _parse_date(period_end_raw) if period_end_raw else None
        due_date = _parse_date(due_date_raw) if due_date_raw else None
        if period_start_raw and not period_start:
            flash('Period from must be a valid date.', 'danger')
            return redirect(url_for('subcontract_bills', company_id=company_id, subcontractor_id=sub_id_raw))
        if period_end_raw and not period_end:
            flash('Period to must be a valid date.', 'danger')
            return redirect(url_for('subcontract_bills', company_id=company_id, subcontractor_id=sub_id_raw))
        if due_date_raw and not due_date:
            flash('Due date must be a valid date.', 'danger')
            return redirect(url_for('subcontract_bills', company_id=company_id, subcontractor_id=sub_id_raw))

        if period_start and period_end and period_start > period_end:
            flash('Period from cannot be after period to.', 'danger')
            return redirect(url_for('subcontract_bills', company_id=company_id, subcontractor_id=sub_id_raw))

        try:
            sub_id = int(sub_id_raw)
        except Exception:
            flash('Supplier selection is invalid.', 'danger')
            return redirect(url_for('subcontract_bills', company_id=company_id))

        subcontractor = db.session.get(Subcontractor, sub_id)
        if not subcontractor:
            flash('Supplier not found.', 'danger')
            return redirect(url_for('subcontract_bills', company_id=company_id))

        if company_id_int is None:
            try:
                company_id_int = int(company_id)
            except Exception:
                company_id_int = None
        if company_id_int is None or subcontractor.company_id != company_id_int:
            flash('Supplier does not belong to the selected company.', 'danger')
            return redirect(url_for('subcontract_bills', company_id=company_id))

        amount = 0.0
        hours = 0.0
        hours_by_date = None
        if use_hours:
            hours_from_days = 0.0
            hours_by_date_map: dict[str, float] = {}
            for key, value in request.form.items():
                if not key.startswith('hours_day_'):
                    continue
                date_key = key.replace('hours_day_', '').strip()
                try:
                    hours_val = float(value or 0)
                except Exception:
                    hours_val = 0.0
                if hours_val > 0:
                    hours_by_date_map[date_key] = hours_val
                    hours_from_days += hours_val

            if hours_from_days > 0:
                hours = hours_from_days
                hours_by_date = json.dumps(hours_by_date_map)
            else:
                try:
                    hours = float(hours_raw)
                except Exception:
                    flash('Hours must be a number.', 'danger')
                    return redirect(url_for('subcontract_bills', company_id=company_id, subcontractor_id=sub_id_raw))

            if hours <= 0:
                flash('Hours must be greater than 0.', 'danger')
                return redirect(url_for('subcontract_bills', company_id=company_id, subcontractor_id=sub_id_raw))

            rate = float(subcontractor.contract_rate or 0.0)
            if rate <= 0:
                flash('Supplier hourly rate is missing. Update the supplier first.', 'danger')
                return redirect(url_for('subcontract_bills', company_id=company_id, subcontractor_id=sub_id_raw))
            amount = hours * rate
        else:
            try:
                amount = float(amount_raw)
            except Exception:
                flash('Amount must be a number.', 'danger')
                return redirect(url_for('subcontract_bills', company_id=company_id, subcontractor_id=sub_id_raw))
            if amount <= 0:
                flash('Amount must be greater than 0.', 'danger')
                return redirect(url_for('subcontract_bills', company_id=company_id, subcontractor_id=sub_id_raw))

        gst_rate = float(subcontractor.gst_rate or 0.13)
        gst_amount = amount * gst_rate if taxable else 0.0
        total = amount + gst_amount

        bill = SubcontractBill(
            company_id=company_id_int,
            subcontractor_id=subcontractor.id,
            bill_date=bill_date,
            period_start=period_start,
            period_end=period_end,
            due_date=due_date,
            use_hours=use_hours,
            hours=hours,
            hours_by_date=hours_by_date,
            taxable=taxable,
            description=description or None,
            amount=amount,
            gst_rate=gst_rate,
            gst_amount=gst_amount,
            total=total,
        )
        db.session.add(bill)
        db.session.commit()
        flash('Bill saved.', 'success')
        return redirect(url_for(
            'subcontract_bills',
            run='1',
            company_id=company_id,
            subcontractor_id=sub_id_raw,
            bill_id=bill.id,
            saved='1',
        ))

    bills = []
    totals = {'amount': 0.0, 'gst': 0.0, 'total': 0.0}
    if run == '1' and schema_ready:
        q = SubcontractBill.query
        if company_id_int is not None:
            q = q.filter(SubcontractBill.company_id == company_id_int)
        if subcontractor_id:
            try:
                q = q.filter(SubcontractBill.subcontractor_id == int(subcontractor_id))
            except Exception:
                q = q
        if date_from:
            q = q.filter(SubcontractBill.bill_date >= date_from)
        if date_to:
            q = q.filter(SubcontractBill.bill_date <= date_to)
        bills = q.order_by(SubcontractBill.bill_date.desc(), SubcontractBill.id.desc()).limit(200).all()
        for b in bills:
            totals['amount'] += float(b.amount or 0.0)
            totals['gst'] += float(b.gst_amount or 0.0)
            totals['total'] += float(b.total or 0.0)

    saved_bill = None
    saved_id_raw = (request.args.get('bill_id') or '').strip()
    if saved_id_raw.isdigit():
        try:
            candidate = db.session.get(SubcontractBill, int(saved_id_raw))
        except Exception:
            candidate = None
        if candidate:
            if _is_admin_session():
                saved_bill = candidate
            else:
                cid = session.get('company_id')
                if cid and int(cid) == int(candidate.company_id or 0):
                    saved_bill = candidate

    return render_template(
        'subcontract_bills.html',
        companies=companies,
        subcontractors=subcontractors,
        bills=bills,
        totals=totals,
        selected_company_id=company_id,
        selected_subcontractor_id=subcontractor_id,
        selected_date_from=date_from,
        selected_date_to=date_to,
        run=run,
        schema_ready=schema_ready,
        saved_bill=saved_bill,
    )


@app.route('/subcontracts/bills/<int:bill_id>/print', methods=['GET'])
@require_login
def subcontract_bill_print(bill_id: int):
    _ensure_subcontract_bill_columns()
    bill = db.session.get(SubcontractBill, bill_id)
    if not bill:
        abort(404)

    if not _is_admin_session():
        cid = session.get('company_id')
        if not cid or int(cid) != int(bill.company_id or 0):
            abort(403)

    qty = 1.0
    rate = float(bill.amount or 0.0)
    hours_by_date_rows: list[dict[str, float | str]] = []
    if bool(bill.use_hours) and float(bill.hours or 0.0) > 0:
        qty = float(bill.hours or 0.0)
        rate = float(bill.amount or 0.0) / qty if qty else 0.0
        if bill.hours_by_date:
            try:
                hours_by_date_map = json.loads(bill.hours_by_date)
            except Exception:
                hours_by_date_map = {}
            for date_key in sorted(hours_by_date_map.keys()):
                try:
                    day_hours = float(hours_by_date_map[date_key])
                except Exception:
                    day_hours = 0.0
                if day_hours <= 0:
                    continue
                hours_by_date_rows.append({
                    'date': date_key,
                    'hours': day_hours,
                    'amount': day_hours * rate,
                })

    tax_label = 'GST/HST' if bool(bill.taxable) else 'Exempt'

    return render_template(
        'subcontract_bill_print.html',
        bill=bill,
        qty=qty,
        rate=rate,
        tax_label=tax_label,
        hours_by_date_rows=hours_by_date_rows,
    )


@app.route('/subcontracts/bills/<int:bill_id>/edit', methods=['GET', 'POST'])
@require_login
def edit_subcontract_bill(bill_id: int):
    _ensure_subcontract_bill_columns()
    bill = db.session.get(SubcontractBill, bill_id)
    if not bill:
        abort(404)

    if not _is_admin_session():
        cid = session.get('company_id')
        if not cid or int(cid) != int(bill.company_id or 0):
            abort(403)

    company_id_int = int(bill.company_id or 0)
    company = db.session.get(Company, company_id_int)

    subcontractors = (
        Subcontractor.query
        .filter(Subcontractor.company_id == company_id_int)
        .order_by(Subcontractor.contractor_company_name.asc())
        .all()
    )

    if request.method == 'POST':
        bill_date_raw = (request.form.get('bill_date') or '').strip()
        period_start_raw = (request.form.get('period_start') or '').strip()
        period_end_raw = (request.form.get('period_end') or '').strip()
        due_date_raw = (request.form.get('due_date') or '').strip()
        amount_raw = (request.form.get('amount') or '').strip()
        hours_raw = (request.form.get('hours') or '').strip()
        description = (request.form.get('description') or '').strip()
        sub_id_raw = (request.form.get('subcontractor_id') or '').strip()
        use_hours = (request.form.get('use_hours') or '').strip().lower() in {'1', 'true', 'on', 'yes'}
        taxable = (request.form.get('taxable') or '').strip().lower() in {'1', 'true', 'on', 'yes'}

        bill_date = _parse_date(bill_date_raw)
        if not bill_date:
            flash('Bill date is required.', 'danger')
            return redirect(url_for('edit_subcontract_bill', bill_id=bill.id))

        period_start = _parse_date(period_start_raw) if period_start_raw else None
        period_end = _parse_date(period_end_raw) if period_end_raw else None
        due_date = _parse_date(due_date_raw) if due_date_raw else None
        if period_start_raw and not period_start:
            flash('Period from must be a valid date.', 'danger')
            return redirect(url_for('edit_subcontract_bill', bill_id=bill.id))
        if period_end_raw and not period_end:
            flash('Period to must be a valid date.', 'danger')
            return redirect(url_for('edit_subcontract_bill', bill_id=bill.id))
        if due_date_raw and not due_date:
            flash('Due date must be a valid date.', 'danger')
            return redirect(url_for('edit_subcontract_bill', bill_id=bill.id))

        if period_start and period_end and period_start > period_end:
            flash('Period from cannot be after period to.', 'danger')
            return redirect(url_for('edit_subcontract_bill', bill_id=bill.id))

        try:
            sub_id = int(sub_id_raw)
        except Exception:
            flash('Supplier selection is invalid.', 'danger')
            return redirect(url_for('edit_subcontract_bill', bill_id=bill.id))

        subcontractor = db.session.get(Subcontractor, sub_id)
        if not subcontractor or int(subcontractor.company_id or 0) != company_id_int:
            flash('Supplier does not belong to this company.', 'danger')
            return redirect(url_for('edit_subcontract_bill', bill_id=bill.id))

        amount = 0.0
        hours = 0.0
        hours_by_date = None
        if use_hours:
            hours_from_days = 0.0
            hours_by_date_map: dict[str, float] = {}
            for key, value in request.form.items():
                if not key.startswith('hours_day_'):
                    continue
                date_key = key.replace('hours_day_', '').strip()
                try:
                    hours_val = float(value or 0)
                except Exception:
                    hours_val = 0.0
                if hours_val > 0:
                    hours_by_date_map[date_key] = hours_val
                    hours_from_days += hours_val

            if hours_from_days > 0:
                hours = hours_from_days
                hours_by_date = json.dumps(hours_by_date_map)
            else:
                try:
                    hours = float(hours_raw)
                except Exception:
                    flash('Hours must be a number.', 'danger')
                    return redirect(url_for('edit_subcontract_bill', bill_id=bill.id))

            if hours <= 0:
                flash('Hours must be greater than 0.', 'danger')
                return redirect(url_for('edit_subcontract_bill', bill_id=bill.id))

            rate = float(subcontractor.contract_rate or 0.0)
            if rate <= 0:
                flash('Supplier hourly rate is missing. Update the supplier first.', 'danger')
                return redirect(url_for('edit_subcontract_bill', bill_id=bill.id))
            amount = hours * rate
        else:
            try:
                amount = float(amount_raw)
            except Exception:
                flash('Amount must be a number.', 'danger')
                return redirect(url_for('edit_subcontract_bill', bill_id=bill.id))
            if amount <= 0:
                flash('Amount must be greater than 0.', 'danger')
                return redirect(url_for('edit_subcontract_bill', bill_id=bill.id))

        gst_rate = float(subcontractor.gst_rate or 0.13)
        gst_amount = amount * gst_rate if taxable else 0.0
        total = amount + gst_amount

        bill.subcontractor_id = subcontractor.id
        bill.bill_date = bill_date
        bill.period_start = period_start
        bill.period_end = period_end
        bill.due_date = due_date
        bill.use_hours = use_hours
        bill.hours = hours
        bill.hours_by_date = hours_by_date
        bill.taxable = taxable
        bill.description = description or None
        bill.amount = amount
        bill.gst_rate = gst_rate
        bill.gst_amount = gst_amount
        bill.total = total

        db.session.commit()
        flash('Bill updated.', 'success')
        return redirect(url_for('subcontract_bills', run='1', company_id=company_id_int, subcontractor_id=sub_id, bill_id=bill.id))

    hours_by_date_data = {}
    if bill.hours_by_date:
        try:
            hours_by_date_data = json.loads(bill.hours_by_date) or {}
        except Exception:
            hours_by_date_data = {}

    return render_template(
        'edit_subcontract_bill.html',
        bill=bill,
        company=company,
        subcontractors=subcontractors,
        hours_by_date_data=hours_by_date_data,
    )


@app.route('/subcontracts/bills/<int:bill_id>/delete', methods=['POST'])
@require_login
def delete_subcontract_bill(bill_id: int):
    _ensure_subcontract_bill_columns()
    bill = db.session.get(SubcontractBill, bill_id)
    if not bill:
        abort(404)

    if not _is_admin_session():
        cid = session.get('company_id')
        if not cid or int(cid) != int(bill.company_id or 0):
            abort(403)

    company_id = bill.company_id
    db.session.delete(bill)
    db.session.commit()
    flash('Bill deleted.', 'success')
    return redirect(url_for('subcontract_bills', run='1', company_id=company_id))


@app.route('/subcontracts/reports', methods=['GET', 'POST'])
@require_login
def subcontract_reports():
    _ensure_subcontract_bill_columns()
    schema_ready = _is_subcontract_bill_schema_ready()
    if _is_admin_session():
        companies = Company.query.order_by(Company.name).all()
    else:
        cid = session.get('company_id')
        companies = Company.query.filter(Company.id == int(cid)).order_by(Company.name).all() if cid else []

    run = (request.values.get('run') or '').strip()
    company_id = (request.values.get('company_id') or '').strip()
    subcontractor_id = (request.values.get('subcontractor_id') or '').strip()
    date_from = (request.values.get('date_from') or '').strip()
    date_to = (request.values.get('date_to') or '').strip()

    if _is_owner_session():
        company_id = str(session.get('company_id') or '').strip()

    allowed_company_ids = _allowed_company_ids_for_session()
    company_id_int = None
    if company_id:
        try:
            company_id_int = int(company_id)
        except Exception:
            company_id_int = None
        if company_id_int is not None and company_id_int not in allowed_company_ids:
            abort(403)

    subs_query = Subcontractor.query
    if company_id_int is not None:
        subs_query = subs_query.filter(Subcontractor.company_id == company_id_int)
    elif not _is_admin_session():
        subs_query = subs_query.filter(Subcontractor.company_id == -1)

    subcontractors = subs_query.order_by(Subcontractor.contractor_company_name.asc()).all()

    bills = []
    totals = {'amount': 0.0, 'gst': 0.0, 'total': 0.0}
    require_company_filter = False
    if (run == '1' or request.method == 'POST') and schema_ready:
        if _is_admin_session() and company_id_int is None:
            require_company_filter = True
        else:
            q = SubcontractBill.query
            if company_id_int is not None:
                q = q.filter(SubcontractBill.company_id == company_id_int)
            if subcontractor_id:
                try:
                    q = q.filter(SubcontractBill.subcontractor_id == int(subcontractor_id))
                except Exception:
                    q = q
            if date_from:
                q = q.filter(SubcontractBill.bill_date >= date_from)
            if date_to:
                q = q.filter(SubcontractBill.bill_date <= date_to)
            bills = q.order_by(SubcontractBill.bill_date.desc(), SubcontractBill.id.desc()).all()
            for b in bills:
                totals['amount'] += float(b.amount or 0.0)
                totals['gst'] += float(b.gst_amount or 0.0)
                totals['total'] += float(b.total or 0.0)

    show_supplier_column = not subcontractor_id
    return render_template(
        'subcontract_reports.html',
        companies=companies,
        subcontractors=subcontractors,
        bills=bills,
        totals=totals,
        selected_company_id=company_id,
        selected_subcontractor_id=subcontractor_id,
        selected_date_from=date_from,
        selected_date_to=date_to,
        run=run,
        schema_ready=schema_ready,
        require_company_filter=require_company_filter,
        show_supplier_column=show_supplier_column,
    )


@app.route('/subcontracts/reports/pdf', methods=['GET'])
@require_login
def subcontract_reports_pdf():
    _ensure_subcontract_bill_columns()
    if not _is_subcontract_bill_schema_ready():
        abort(503)
    import io
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

    company_id = (request.args.get('company_id') or '').strip()
    subcontractor_id = (request.args.get('subcontractor_id') or '').strip()
    date_from = (request.args.get('date_from') or '').strip()
    date_to = (request.args.get('date_to') or '').strip()

    if _is_owner_session():
        company_id = str(session.get('company_id') or '').strip()

    allowed_company_ids = _allowed_company_ids_for_session()
    company_id_int = None
    if company_id:
        try:
            company_id_int = int(company_id)
        except Exception:
            company_id_int = None
        if company_id_int is not None and company_id_int not in allowed_company_ids:
            abort(403)

    if _is_admin_session() and company_id_int is None:
        abort(400)

    q = SubcontractBill.query
    if company_id_int is not None:
        q = q.filter(SubcontractBill.company_id == company_id_int)
    if subcontractor_id:
        try:
            q = q.filter(SubcontractBill.subcontractor_id == int(subcontractor_id))
        except Exception:
            q = q
    if date_from:
        q = q.filter(SubcontractBill.bill_date >= date_from)
    if date_to:
        q = q.filter(SubcontractBill.bill_date <= date_to)

    bills = q.order_by(SubcontractBill.bill_date.desc(), SubcontractBill.id.desc()).all()
    show_supplier_column = not subcontractor_id

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('ReportTitle', parent=styles['Heading2'], alignment=TA_CENTER, textColor=colors.HexColor('#3b82f6'))
    label_style = ParagraphStyle('Label', parent=styles['BodyText'], textColor=colors.HexColor('#6b7280'))
    value_style = ParagraphStyle('Value', parent=styles['BodyText'])
    meta_right = ParagraphStyle('MetaRight', parent=styles['BodyText'], alignment=TA_RIGHT)
    story = []

    def _money(value: float) -> str:
        try:
            return f"${float(value):,.2f}"
        except Exception:
            return "$0.00"

    def _format_address_lines(raw: str) -> str:
        if not raw:
            return ''
        if '\n' in raw:
            parts = [p.strip() for p in raw.split('\n') if p.strip()]
        else:
            parts = [p.strip() for p in raw.split(',') if p.strip()]
        return '<br/>'.join(parts)

    if not bills:
        story.append(Paragraph('No subcontract bills match the selected filters.', styles['BodyText']))
    else:
        first_bill = bills[0]
        company = first_bill.company
        supplier_obj = first_bill.subcontractor
        company_name = company.name if company else ''
        company_address = _format_address_lines(company.address) if company and company.address else ''
        company_hst = f"HST Number # {company.business_number} RT0001" if company and company.business_number else ''
        supplier = supplier_obj.contractor_company_name if supplier_obj else ''
        supplier_address = _format_address_lines(supplier_obj.address) if supplier_obj and supplier_obj.address else ''
        supplier_hst = f"HST Number # {supplier_obj.tax_number} RT 0001" if supplier_obj and supplier_obj.tax_number else ''

        story.append(Paragraph('Reports', title_style))
        story.append(Spacer(1, 6))

        header_tbl = Table(
            [
                [
                    Paragraph(f"<b>{company_name}</b><br/>{company_address}<br/>{company_hst}", value_style),
                    Paragraph(f"<b>Period</b><br/>{date_from} - {date_to}", meta_right),
                ],
            ],
            colWidths=[doc.width * 0.7, doc.width * 0.3],
        )
        header_tbl.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ]))
        story.append(header_tbl)
        story.append(Spacer(1, 8))

        if not show_supplier_column:
            story.append(Spacer(1, 10))

            supplier_tbl = Table(
                [
                    [
                        Paragraph("<font color='#2b5a85'><b>Supplier</b></font>", value_style),
                    ],
                    [
                        Paragraph(f"<b>{supplier}</b><br/>{supplier_address}<br/>{supplier_hst}", value_style),
                    ],
                ],
                colWidths=[doc.width],
            )
            supplier_tbl.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ]))
            story.append(supplier_tbl)
            story.append(Spacer(1, 10))

        if show_supplier_column:
            line_rows = [['DATE', 'SUPPLIER', 'DESCRIPTION', 'SUBTOTAL', 'GST/HST', 'TOTAL']]
        else:
            line_rows = [['DATE', 'DESCRIPTION', 'SUBTOTAL', 'GST/HST', 'TOTAL']]
        total_amount = 0.0
        total_gst = 0.0
        total_all = 0.0
        for b in bills:
            amount = float(b.amount or 0.0)
            gst_amount = float(b.gst_amount or 0.0)
            total = float(b.total or 0.0)
            total_amount += amount
            total_gst += gst_amount
            total_all += total
            if show_supplier_column:
                line_rows.append([
                    b.bill_date.strftime('%Y-%m-%d') if b.bill_date else '',
                    b.subcontractor.contractor_company_name if b.subcontractor else '',
                    b.description or 'Subcontract',
                    _money(amount),
                    _money(gst_amount),
                    _money(total),
                ])
            else:
                line_rows.append([
                    b.bill_date.strftime('%Y-%m-%d') if b.bill_date else '',
                    b.description or 'Subcontract',
                    _money(amount),
                    _money(gst_amount),
                    _money(total),
                ])

        if show_supplier_column:
            line_tbl = Table(
                line_rows,
                colWidths=[1.0 * inch, 1.6 * inch, 2.2 * inch, 1.0 * inch, 1.0 * inch, 1.0 * inch],
            )
        else:
            line_tbl = Table(
                line_rows,
                colWidths=[1.2 * inch, 2.9 * inch, 1.2 * inch, 1.1 * inch, 1.1 * inch],
            )
        line_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#eef3f8')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#2b5a85')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('LINEBELOW', (0, 0), (-1, 0), 0.5, colors.HexColor('#cbd5e1')),
            ('LINEBELOW', (0, 1), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ALIGN', (2, 1), (-1, -1), 'RIGHT'),
            ('ALIGN', (2, 0), (-1, 0), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(line_tbl)
        story.append(Spacer(1, 8))

        totals_tbl = Table(
            [
                ['Subtotal', _money(total_amount)],
                ['Sales Tax Total', _money(total_gst)],
                ['Total', _money(total_all)],
            ],
            colWidths=[doc.width * 0.75, doc.width * 0.25],
        )
        totals_tbl.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (-1, -1), 'RIGHT'),
            ('LINEABOVE', (0, 2), (-1, 2), 0.5, colors.HexColor('#cbd5e1')),
        ]))
        story.append(totals_tbl)

    doc.build(story)
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name='subcontract_reports.pdf',
    )


@app.route('/subcontracts/<int:sub_id>/edit', methods=['GET', 'POST'])
@require_login
def edit_subcontractor(sub_id: int):
    sub = db.session.get(Subcontractor, sub_id)
    if not sub:
        abort(404)

    if not _is_admin_session():
        company_id = session.get('company_id')
        if not company_id or sub.company_id != int(company_id):
            abort(403)

    if _is_admin_session():
        companies = Company.query.order_by(Company.name).all()
    else:
        cid = session.get('company_id')
        companies = Company.query.filter(Company.id == int(cid)).order_by(Company.name).all() if cid else []

    if request.method == 'POST':
        company_id_raw = (request.form.get('company_id') or '').strip()
        contractor_company_name = (request.form.get('contractor_company_name') or '').strip()
        address = (request.form.get('contractor_address') or '').strip()
        tax_number = (request.form.get('tax_number') or '').strip()
        contract_rate_raw = (request.form.get('contract_rate') or '').strip()

        if _is_owner_session():
            company_id_raw = str(session.get('company_id') or '').strip()

        try:
            company_id = int(company_id_raw) if company_id_raw else None
        except Exception:
            company_id = None

        if not company_id:
            flash('Company is required.', 'danger')
            return render_template('edit_subcontractor.html', subcontractor=sub, companies=companies)

        allowed_company_ids = _allowed_company_ids_for_session()
        if company_id not in allowed_company_ids:
            abort(403)

        if not contractor_company_name:
            flash('Sub-contract company name is required.', 'danger')
            return render_template('edit_subcontractor.html', subcontractor=sub, companies=companies)

        if not address:
            flash('Address is required.', 'danger')
            return render_template('edit_subcontractor.html', subcontractor=sub, companies=companies)

        try:
            contract_rate = float(contract_rate_raw)
        except Exception:
            flash('Contract rate must be a number.', 'danger')
            return render_template('edit_subcontractor.html', subcontractor=sub, companies=companies)

        if contract_rate < 0:
            flash('Contract rate cannot be negative.', 'danger')
            return render_template('edit_subcontractor.html', subcontractor=sub, companies=companies)

        sub.company_id = company_id
        sub.contractor_company_name = contractor_company_name
        sub.address = address
        sub.tax_number = tax_number
        sub.contract_rate = contract_rate
        db.session.commit()
        flash('Sub-contract updated.', 'success')
        return redirect(url_for('manage_subcontracts', run='1', company_id=company_id))

    return render_template('edit_subcontractor.html', subcontractor=sub, companies=companies)


@app.route('/subcontracts/<int:sub_id>/delete', methods=['POST'])
@require_login
def delete_subcontractor(sub_id: int):
    sub = db.session.get(Subcontractor, sub_id)
    if not sub:
        abort(404)
    if not _is_admin_session():
        company_id = session.get('company_id')
        if not company_id or sub.company_id != int(company_id):
            abort(403)
    db.session.delete(sub)
    db.session.commit()
    flash('Sub-contract deleted.', 'success')
    return redirect(url_for('manage_subcontracts', run='1'))


@app.route('/employees/<int:employee_id>/delete', methods=['POST'])
@require_login
def delete_employee(employee_id):
    e = db.session.get(Employee, employee_id)
    if not e:
        abort(404)
    _require_employee_access(e)
    PayrollSubmission.query.filter(PayrollSubmission.employee_id == e.id).delete(synchronize_session=False)
    PayrollLine.query.filter(PayrollLine.employee_id == e.id).delete(synchronize_session=False)
    db.session.delete(e)
    db.session.commit()
    flash('Employee deleted.', 'success')
    return redirect(url_for('employees'))


@app.route('/employees/<int:employee_id>/edit', methods=['GET', 'POST'])
@require_login
def edit_employee(employee_id):
    e = db.session.get(Employee, employee_id)
    if not e:
        abort(404)
    _require_employee_access(e)

    if _is_admin_session():
        companies = Company.query.all()
    else:
        cid = session.get('company_id')
        companies = Company.query.filter(Company.id == int(cid)).all() if cid else []
    if request.method == 'POST':
        e.first_name = request.form.get('first_name')
        e.last_name = request.form.get('last_name')
        e.address = request.form.get('address')
        e.sin = request.form.get('sin')
        raw_hire = request.form.get('hire_date') or None
        if raw_hire:
            try:
                e.hire_date = datetime.date.fromisoformat(raw_hire)
            except Exception:
                e.hire_date = None
        else:
            e.hire_date = None
        e.payroll_frequency = request.form.get('payroll_frequency')
        e.pay_rate = float(request.form.get('pay_rate') or 0)
        vacation_pay_raw = (request.form.get('vacation_pay') or '').strip().lower()
        ei_exempt_raw = (request.form.get('ei_exempt') or '').strip().lower()
        e.vacation_pay_enabled = vacation_pay_raw in {'yes', '1', 'true', 'on'}
        e.ei_exempt = ei_exempt_raw in {'yes', '1', 'true', 'on'}
        if _is_owner_session():
            e.company_id = session.get('company_id') or None
        else:
            e.company_id = request.form.get('company_id') or None
        e.annual_salary = float(request.form.get('salary') or 0)
        db.session.commit()
        flash('Employee updated.', 'success')
        return redirect(url_for('employees'))
    return render_template('edit_employee.html', employee=e, companies=companies)


@app.route('/data-entry', methods=['GET', 'POST'])
@require_admin
def data_entry():
    companies = Company.query.all()
    employees = Employee.query.order_by(Employee.first_name, Employee.last_name).all()
    selected_company_id = (request.values.get('company_id') or '').strip()
    result = None
    if request.method == 'POST':
        action = (request.form.get('action') or 'preview').strip().lower()
        company_id_raw = (request.form.get('company_id') or '').strip()
        emp_id = request.form.get('employee_id')
        hours_raw = (request.form.get('total_hours') or '').strip()
        gross_raw = (request.form.get('gross') or '').strip()
        employee = db.session.get(Employee, int(emp_id)) if emp_id else None

        if not company_id_raw:
            flash('Company is required.', 'danger')
            return redirect(url_for('data_entry'))

        try:
            company_id_int = int(company_id_raw)
        except Exception:
            flash('Company selection is invalid.', 'danger')
            return redirect(url_for('data_entry'))

        allowed_company_ids = _allowed_company_ids_for_session()
        if company_id_int not in allowed_company_ids:
            abort(403)

        if employee and int(employee.company_id or 0) != company_id_int:
            flash('Selected employee does not belong to the selected company.', 'danger')
            return redirect(url_for('data_entry'))

        hours = 0.0
        if hours_raw:
            try:
                hours = float(hours_raw)
            except Exception:
                flash('Total hours must be a number.', 'danger')
                return redirect(url_for('data_entry'))
            if hours < 0:
                flash('Total hours cannot be negative.', 'danger')
                return redirect(url_for('data_entry'))

        pay_rate_used = 0.0
        if employee:
            pay_rate_used = float(employee.pay_rate or 0.0)

        # Gross can be entered manually, or calculated as hours × employee pay rate.
        # If employee has Vacation Pay enabled, add 4% Vacation Pay on top for calculation.
        regular_gross = None
        if gross_raw:
            try:
                regular_gross = float(gross_raw)
            except Exception:
                flash('Gross pay must be a number.', 'danger')
                return redirect(url_for('data_entry'))
        else:
            if employee:
                if not hours_raw:
                    flash('Total hours is required when an employee is selected (gross is calculated automatically).', 'danger')
                    return redirect(url_for('data_entry'))
                if pay_rate_used <= 0:
                    flash('Selected employee has no pay rate set. Please update employee Pay rate.', 'danger')
                    return redirect(url_for('data_entry'))
                regular_gross = hours * pay_rate_used
            else:
                flash('Gross pay is required (or select an employee and enter total hours).', 'danger')
                return redirect(url_for('data_entry'))

        if regular_gross is None:
            flash('Gross pay is required.', 'danger')
            return redirect(url_for('data_entry'))

        vacation_pay = 0.0
        if employee and bool(getattr(employee, 'vacation_pay_enabled', False)):
            vacation_pay = 0.04 * float(regular_gross or 0.0)

        gross = float(regular_gross or 0.0) + float(vacation_pay or 0.0)
        period_start = request.form.get('period_start') or None
        period_end = request.form.get('period_end') or None
        pay_date = request.form.get('pay_date') or None
        def _parse_date(s):
            if not s:
                return None
            try:
                return datetime.date.fromisoformat(s)
            except Exception:
                return None
        period_start = _parse_date(period_start)
        period_end = _parse_date(period_end)
        pay_date = _parse_date(pay_date)
        if not pay_date:
            pay_date = datetime.date.today()

        pay_periods = 26
        if employee and employee.payroll_frequency:
            freq = (employee.payroll_frequency or '').strip().lower()
            if freq == 'weekly':
                pay_periods = 52
            elif freq in {'bi-weekly', 'biweekly'}:
                pay_periods = 26
            elif freq == 'monthly':
                pay_periods = 12

        ytd_cpp = 0.0
        ytd_cpp2 = 0.0
        ytd_ei_emp = 0.0
        ytd_ei_employer = 0.0
        if employee:
            year_start = datetime.date(pay_date.year, 1, 1)
            year_end = datetime.date(pay_date.year, 12, 31)
            ytd_filter = [
                PayrollLine.employee_id == employee.id,
                PayrollLine.pay_date >= year_start,
                PayrollLine.pay_date <= year_end,
                PayrollLine.pay_date < pay_date,
            ]
            ytd_cpp = float(
                db.session.query(func.coalesce(func.sum(PayrollLine.cpp_employee), 0.0))
                .filter(*ytd_filter)
                .scalar()
                or 0.0
            )
            ytd_cpp2 = float(
                db.session.query(func.coalesce(func.sum(PayrollLine.cpp2_employee), 0.0))
                .filter(*ytd_filter)
                .scalar()
                or 0.0
            )
            ytd_ei_emp = float(
                db.session.query(func.coalesce(func.sum(PayrollLine.ei_employee), 0.0))
                .filter(*ytd_filter)
                .scalar()
                or 0.0
            )
            ytd_ei_employer = float(
                db.session.query(func.coalesce(func.sum(PayrollLine.ei_employer), 0.0))
                .filter(*ytd_filter)
                .scalar()
                or 0.0
            )

        result = calculate_payroll(
            gross,
            pay_periods_per_year=pay_periods,
            ytd_cpp_employee=ytd_cpp,
            ytd_cpp2_employee=ytd_cpp2,
            ytd_ei_employee=ytd_ei_emp,
            ytd_ei_employer=ytd_ei_employer,
            ei_exempt=bool(employee and bool(getattr(employee, 'ei_exempt', False))),
        )

        # Attach UI context for display
        result.setdefault('meta', {})
        result['meta']['total_hours'] = round(hours, 2)
        result['meta']['pay_rate_used'] = round(pay_rate_used, 2)
        result['meta']['vacation_pay_enabled'] = bool(employee and bool(getattr(employee, 'vacation_pay_enabled', False)))
        result['meta']['vacation_pay'] = round(float(vacation_pay or 0.0), 2)

        if result.get('meta', {}).get('cpp_max_reached'):
            flash('Max limit reached: CPP maximum contribution for the year.', 'danger')
        if result.get('meta', {}).get('cpp2_max_reached'):
            flash('Max limit reached: Second CPP (CPP2) maximum contribution for the year.', 'danger')
        if result.get('meta', {}).get('ei_max_reached'):
            flash('Max limit reached: EI maximum premium for the year.', 'danger')

        # Preview: do not save anything
        if action == 'preview':
            flash('Preview ready (not saved).', 'info')
            return render_template('data_entry.html', companies=companies, employees=employees, result=result, mode='preview')

        # Submit: must have an employee to save
        if action == 'submit' and not employee:
            flash('Select an employee before submitting. Use Preview to calculate without saving.', 'danger')
            return render_template('data_entry.html', companies=companies, employees=employees, result=result, mode='preview')

        # Save payroll line
        if employee and action == 'submit':
            pl = PayrollLine(
                employee_id=employee.id,
                hours=hours,
                vacation_pay=float(vacation_pay or 0.0),
                gross=gross,
                net=result['net_pay'],
                cpp_employee=result['cpp_employee'],
                cpp2_employee=result.get('cpp2_employee', 0.0),
                ei_employee=result['ei_employee'],
                ei_employer=result['ei_employer'],
                cpp2_employer=result.get('cpp2_employer', 0.0),
                federal_tax=result['federal_tax'],
                ontario_tax=result['ontario_tax'],
                total_employee_deductions=result['total_employee_deductions'],
                employer_total_cost=result['employer_total_cost'],
                total_remittance=result['total_remittance'],
                period_start=period_start or None,
                period_end=period_end or None,
                pay_date=pay_date or None,
            )
            db.session.add(pl)
            db.session.commit()
            flash('Payroll line saved.', 'success')
        else:
            flash('Calculation complete.', 'info')
    return render_template(
        'data_entry.html',
        companies=companies,
        employees=employees,
        selected_company_id=selected_company_id,
        result=result,
        mode='submit',
    )


@app.route('/manage/data', methods=['GET'])
@require_admin
def manage_data():
    companies = Company.query.order_by(Company.name).all()
    employees = []

    run = (request.args.get('run') or '').strip()

    company_id = (request.args.get('company_id') or '').strip()
    employee_id = (request.args.get('employee_id') or '').strip()
    date_from = (request.args.get('date_from') or '').strip()
    date_to = (request.args.get('date_to') or '').strip()

    require_company_filter = False
    if company_id:
        try:
            employees = (
                Employee.query
                .filter(Employee.company_id == int(company_id))
                .order_by(Employee.first_name, Employee.last_name)
                .all()
            )
        except Exception:
            employees = []
    else:
        require_company_filter = True

    lines = []
    if run == '1':
        if not company_id:
            require_company_filter = True
        else:
            q = PayrollLine.query.join(Employee)
            q = q.filter(Employee.company_id == int(company_id))
            if employee_id:
                q = q.filter(PayrollLine.employee_id == int(employee_id))
            if date_from:
                q = q.filter(PayrollLine.pay_date >= date_from)
            if date_to:
                q = q.filter(PayrollLine.pay_date <= date_to)
            lines = q.order_by(PayrollLine.pay_date.desc(), PayrollLine.id.desc()).limit(200).all()

    # Used by Edit links to return to the filtered view.
    next_url = request.full_path or url_for('manage_data')
    next_url_encoded = quote(next_url, safe='')

    return render_template(
        'manage_data.html',
        companies=companies,
        employees=employees,
        lines=lines,
        selected_company_id=company_id,
        selected_employee_id=employee_id,
        selected_date_from=date_from,
        selected_date_to=date_to,
        next_url_encoded=next_url_encoded,
        run=run,
        require_company_filter=require_company_filter,
    )


@app.route('/owner/payroll', methods=['GET', 'POST'])
@require_login
def owner_payroll():
    if not _is_owner_session():
        abort(403)

    company_id = session.get('company_id')
    if not company_id:
        abort(403)

    company_id_int = int(company_id)
    employees = (
        Employee.query.filter(Employee.company_id == company_id_int)
        .order_by(Employee.first_name, Employee.last_name)
        .all()
    )

    if request.method == 'POST':
        period_start_raw = (request.form.get('period_start') or '').strip()
        period_end_raw = (request.form.get('period_end') or '').strip()
        pay_date_raw = (request.form.get('pay_date') or '').strip()

        period_start = None
        period_end = None
        if period_start_raw:
            try:
                period_start = datetime.date.fromisoformat(period_start_raw)
            except Exception:
                flash('Period start must be a valid date.', 'danger')
                return redirect(url_for('owner_payroll'))
        if period_end_raw:
            try:
                period_end = datetime.date.fromisoformat(period_end_raw)
            except Exception:
                flash('Period end must be a valid date.', 'danger')
                return redirect(url_for('owner_payroll'))

        try:
            pay_date = datetime.date.fromisoformat(pay_date_raw)
        except Exception:
            flash('Pay date must be a valid date.', 'danger')
            return redirect(url_for('owner_payroll'))

        if period_start and period_end and period_start > period_end:
            flash('Period start cannot be after period end.', 'danger')
            return redirect(url_for('owner_payroll'))

        submitted = 0
        created_lines: list[PayrollLine] = []
        touched_employee_ids: set[int] = set()
        for e in employees:
            include_raw = (request.form.get(f'include_{e.id}') or '').strip().lower()
            if include_raw != 'on':
                continue

            hours_raw = (request.form.get(f'hours_{e.id}') or '').strip()
            if not hours_raw:
                flash(f'Hours are required for {e.first_name} {e.last_name}.', 'danger')
                return redirect(url_for('owner_payroll'))

            try:
                hours = float(hours_raw)
            except Exception:
                flash(f'Hours must be a number for {e.first_name} {e.last_name}.', 'danger')
                return redirect(url_for('owner_payroll'))

            if hours < 0:
                flash(f'Hours cannot be negative for {e.first_name} {e.last_name}.', 'danger')
                return redirect(url_for('owner_payroll'))

            pay_rate_used = float(e.pay_rate or 0.0)
            regular_gross = hours * pay_rate_used
            vacation_pay = 0.0
            if bool(getattr(e, 'vacation_pay_enabled', False)):
                vacation_pay = 0.04 * float(regular_gross or 0.0)
            gross = float(regular_gross or 0.0) + float(vacation_pay or 0.0)

            pay_periods = 26
            if e.payroll_frequency:
                freq = (e.payroll_frequency or '').strip().lower()
                if freq == 'weekly':
                    pay_periods = 52
                elif freq in {'bi-weekly', 'biweekly'}:
                    pay_periods = 26
                elif freq == 'monthly':
                    pay_periods = 12

            ytd_cpp = 0.0
            ytd_cpp2 = 0.0
            ytd_ei_emp = 0.0
            ytd_ei_employer = 0.0
            year_start = datetime.date(pay_date.year, 1, 1)
            year_end = datetime.date(pay_date.year, 12, 31)
            ytd_filter = [
                PayrollLine.employee_id == e.id,
                PayrollLine.pay_date >= year_start,
                PayrollLine.pay_date <= year_end,
                PayrollLine.pay_date < pay_date,
            ]
            ytd_cpp = float(
                db.session.query(func.coalesce(func.sum(PayrollLine.cpp_employee), 0.0))
                .filter(*ytd_filter)
                .scalar()
                or 0.0
            )
            ytd_cpp2 = float(
                db.session.query(func.coalesce(func.sum(PayrollLine.cpp2_employee), 0.0))
                .filter(*ytd_filter)
                .scalar()
                or 0.0
            )
            ytd_ei_emp = float(
                db.session.query(func.coalesce(func.sum(PayrollLine.ei_employee), 0.0))
                .filter(*ytd_filter)
                .scalar()
                or 0.0
            )
            ytd_ei_employer = float(
                db.session.query(func.coalesce(func.sum(PayrollLine.ei_employer), 0.0))
                .filter(*ytd_filter)
                .scalar()
                or 0.0
            )

            result = calculate_payroll(
                gross,
                pay_periods_per_year=pay_periods,
                ytd_cpp_employee=ytd_cpp,
                ytd_cpp2_employee=ytd_cpp2,
                ytd_ei_employee=ytd_ei_emp,
                ytd_ei_employer=ytd_ei_employer,
                ei_exempt=bool(getattr(e, 'ei_exempt', False)),
            )

            pl = PayrollLine(
                employee_id=e.id,
                hours=hours,
                vacation_pay=float(vacation_pay or 0.0),
                gross=gross,
                net=result['net_pay'],
                cpp_employee=result['cpp_employee'],
                cpp2_employee=result.get('cpp2_employee', 0.0),
                ei_employee=result['ei_employee'],
                ei_employer=result['ei_employer'],
                cpp2_employer=result.get('cpp2_employer', 0.0),
                federal_tax=result['federal_tax'],
                ontario_tax=result['ontario_tax'],
                total_employee_deductions=result['total_employee_deductions'],
                employer_total_cost=result['employer_total_cost'],
                total_remittance=result['total_remittance'],
                period_start=period_start or None,
                period_end=period_end or None,
                pay_date=pay_date or None,
            )
            db.session.add(pl)
            created_lines.append(pl)
            touched_employee_ids.add(e.id)
            submitted += 1

        if submitted == 0:
            flash('Select at least one employee to submit.', 'danger')
            return redirect(url_for('owner_payroll'))

        db.session.flush()
        for employee_id in touched_employee_ids:
            _recalculate_employee_payroll_lines(employee_id)
        db.session.commit()
        session['last_payroll_line_ids'] = [pl.id for pl in created_lines if pl.id]
        session['last_payroll_context'] = {
            'pay_date': pay_date.isoformat() if pay_date else '',
            'period_start': period_start.isoformat() if period_start else '',
            'period_end': period_end.isoformat() if period_end else '',
        }

        return redirect(url_for('owner_payroll_complete'))

    return render_template('owner_payroll.html', employees=employees)


def _build_owner_payroll_preview(employees: list[Employee], company_id_int: int, form: dict) -> dict:
    period_start_raw = (form.get('period_start') or '').strip()
    period_end_raw = (form.get('period_end') or '').strip()
    pay_date_raw = (form.get('pay_date') or '').strip()

    period_start = None
    period_end = None
    if period_start_raw:
        try:
            period_start = datetime.date.fromisoformat(period_start_raw)
        except Exception:
            raise ValueError('Period start must be a valid date.')
    if period_end_raw:
        try:
            period_end = datetime.date.fromisoformat(period_end_raw)
        except Exception:
            raise ValueError('Period end must be a valid date.')

    try:
        pay_date = datetime.date.fromisoformat(pay_date_raw)
    except Exception:
        raise ValueError('Pay date must be a valid date.')

    if period_start and period_end and period_start > period_end:
        raise ValueError('Period start cannot be after period end.')

    rows = []
    totals = {
        'regular_hours': 0.0,
        'total_hours': 0.0,
        'gross': 0.0,
        'employee_deductions': 0.0,
        'net_pay': 0.0,
        'employer_contributions': 0.0,
        'total_payroll_cost': 0.0,
    }
    included = 0

    for e in employees:
        include_raw = (form.get(f'include_{e.id}') or '').strip().lower()
        if include_raw != 'on':
            continue

        hours_raw = (form.get(f'hours_{e.id}') or '').strip()
        if not hours_raw:
            raise ValueError(f'Hours are required for {e.first_name} {e.last_name}.')

        try:
            hours = float(hours_raw)
        except Exception:
            raise ValueError(f'Hours must be a number for {e.first_name} {e.last_name}.')

        if hours < 0:
            raise ValueError(f'Hours cannot be negative for {e.first_name} {e.last_name}.')

        pay_rate_used = float(e.pay_rate or 0.0)
        regular_gross = hours * pay_rate_used
        vacation_pay = 0.0
        if bool(getattr(e, 'vacation_pay_enabled', False)):
            vacation_pay = 0.04 * float(regular_gross or 0.0)
        gross = float(regular_gross or 0.0) + float(vacation_pay or 0.0)

        pay_periods = 26
        if e.payroll_frequency:
            freq = (e.payroll_frequency or '').strip().lower()
            if freq == 'weekly':
                pay_periods = 52
            elif freq in {'bi-weekly', 'biweekly'}:
                pay_periods = 26
            elif freq == 'monthly':
                pay_periods = 12

        year_start = datetime.date(pay_date.year, 1, 1)
        year_end = datetime.date(pay_date.year, 12, 31)
        ytd_filter = [
            PayrollLine.employee_id == e.id,
            PayrollLine.pay_date >= year_start,
            PayrollLine.pay_date <= year_end,
            PayrollLine.pay_date < pay_date,
        ]
        ytd_cpp = float(
            db.session.query(func.coalesce(func.sum(PayrollLine.cpp_employee), 0.0))
            .filter(*ytd_filter)
            .scalar()
            or 0.0
        )
        ytd_cpp2 = float(
            db.session.query(func.coalesce(func.sum(PayrollLine.cpp2_employee), 0.0))
            .filter(*ytd_filter)
            .scalar()
            or 0.0
        )
        ytd_ei_emp = float(
            db.session.query(func.coalesce(func.sum(PayrollLine.ei_employee), 0.0))
            .filter(*ytd_filter)
            .scalar()
            or 0.0
        )
        ytd_ei_employer = float(
            db.session.query(func.coalesce(func.sum(PayrollLine.ei_employer), 0.0))
            .filter(*ytd_filter)
            .scalar()
            or 0.0
        )

        result = calculate_payroll(
            gross,
            pay_periods_per_year=pay_periods,
            ytd_cpp_employee=ytd_cpp,
            ytd_cpp2_employee=ytd_cpp2,
            ytd_ei_employee=ytd_ei_emp,
            ytd_ei_employer=ytd_ei_employer,
            ei_exempt=bool(getattr(e, 'ei_exempt', False)),
        )

        employer_contrib = float(result.get('employer_total_cost', 0.0)) - float(result.get('gross', gross))
        if employer_contrib < 0:
            employer_contrib = 0.0

        rows.append({
            'employee': e,
            'hours': hours,
            'vacation_enabled': bool(getattr(e, 'vacation_pay_enabled', False)),
            'gross': gross,
            'employee_deductions': float(result.get('total_employee_deductions', 0.0)),
            'net_pay': float(result.get('net_pay', 0.0)),
            'employer_contributions': employer_contrib,
        })
        totals['regular_hours'] += hours
        totals['total_hours'] += hours
        totals['gross'] += gross
        totals['employee_deductions'] += float(result.get('total_employee_deductions', 0.0))
        totals['net_pay'] += float(result.get('net_pay', 0.0))
        totals['employer_contributions'] += employer_contrib
        totals['total_payroll_cost'] += float(result.get('employer_total_cost', 0.0))
        included += 1

    if included == 0:
        raise ValueError('Select at least one employee to preview.')

    return {
        'rows': rows,
        'totals': totals,
        'period_start': period_start,
        'period_end': period_end,
        'pay_date': pay_date,
    }


@app.route('/owner/payroll/preview', methods=['POST'])
@require_login
def owner_payroll_preview():
    if not _is_owner_session():
        abort(403)

    company_id = session.get('company_id')
    if not company_id:
        abort(403)

    company_id_int = int(company_id)
    employees = (
        Employee.query.filter(Employee.company_id == company_id_int)
        .order_by(Employee.first_name, Employee.last_name)
        .all()
    )

    try:
        preview = _build_owner_payroll_preview(employees, company_id_int, request.form)
    except ValueError as exc:
        flash(str(exc), 'danger')
        return redirect(url_for('owner_payroll'))

    return render_template('owner_payroll_preview.html', preview=preview)


@app.route('/owner/payroll/complete', methods=['GET'])
@require_login
def owner_payroll_complete():
    if not _is_owner_session():
        abort(403)

    company_id = session.get('company_id')
    if not company_id:
        abort(403)

    line_ids = session.pop('last_payroll_line_ids', None) or []
    context = session.pop('last_payroll_context', None) or {}
    if not line_ids:
        flash('No recent payroll submission found.', 'info')
        return redirect(url_for('owner_payroll'))

    lines = (
        PayrollLine.query
        .join(Employee)
        .filter(PayrollLine.id.in_(line_ids), Employee.company_id == int(company_id))
        .order_by(Employee.first_name.asc(), Employee.last_name.asc())
        .all()
    )

    pay_date = context.get('pay_date') or ''
    period_start = context.get('period_start') or ''
    period_end = context.get('period_end') or ''

    return render_template(
        'owner_payroll_complete.html',
        lines=lines,
        pay_date=pay_date,
        period_start=period_start,
        period_end=period_end,
    )


@app.route('/owner/payroll/edit', methods=['GET'])
@require_login
def owner_payroll_edit():
    if not _is_owner_session():
        abort(403)

    company_id = session.get('company_id')
    if not company_id:
        abort(403)

    employees = (
        Employee.query.filter(Employee.company_id == int(company_id))
        .order_by(Employee.first_name, Employee.last_name)
        .all()
    )

    employee_id = (request.args.get('employee_id') or '').strip()
    date_from_raw = (request.args.get('date_from') or '').strip()
    date_to_raw = (request.args.get('date_to') or '').strip()

    date_from = None
    date_to = None
    if date_from_raw:
        try:
            date_from = datetime.date.fromisoformat(date_from_raw)
        except Exception:
            flash('From date must be a valid date.', 'danger')
            return redirect(url_for('owner_payroll_edit'))

    if date_to_raw:
        try:
            date_to = datetime.date.fromisoformat(date_to_raw)
        except Exception:
            flash('To date must be a valid date.', 'danger')
            return redirect(url_for('owner_payroll_edit'))

    if date_from and date_to and date_from > date_to:
        flash('From date cannot be after To date.', 'danger')
        return redirect(url_for('owner_payroll_edit'))

    lines = []
    if employee_id or date_from or date_to:
        q = (
            PayrollLine.query
            .join(Employee)
            .filter(Employee.company_id == int(company_id))
        )
        if employee_id:
            try:
                q = q.filter(PayrollLine.employee_id == int(employee_id))
            except Exception:
                flash('Employee must be valid.', 'danger')
                return redirect(url_for('owner_payroll_edit'))
        if date_from:
            q = q.filter(PayrollLine.pay_date >= date_from)
        if date_to:
            q = q.filter(PayrollLine.pay_date <= date_to)
        lines = (
            q.order_by(PayrollLine.pay_date.desc(), PayrollLine.id.desc())
            .limit(200)
            .all()
        )

    next_url = request.full_path or url_for('owner_payroll_edit')
    next_url_encoded = quote(next_url, safe='')

    return render_template(
        'owner_payroll_edit.html',
        employees=employees,
        lines=lines,
        selected_employee_id=employee_id,
        selected_date_from=date_from_raw,
        selected_date_to=date_to_raw,
        next_url_encoded=next_url_encoded,
    )


@app.route('/owner/payroll/line/<int:payroll_line_id>/edit', methods=['GET', 'POST'])
@require_login
def owner_edit_payroll_line(payroll_line_id: int):
    if not _is_owner_session():
        abort(403)

    pl = db.session.get(PayrollLine, payroll_line_id)
    if not pl:
        abort(404)

    employee = db.session.get(Employee, pl.employee_id) if pl.employee_id else None
    if not employee or employee.company_id != session.get('company_id'):
        abort(403)

    def _parse_date(s):
        if not s:
            return None
        try:
            return datetime.date.fromisoformat(s)
        except Exception:
            return None

    next_url = (request.args.get('next') or '').strip() or url_for('owner_payroll_edit')
    next_url_encoded = quote(next_url, safe='')

    if request.method == 'POST':
        pay_date = _parse_date((request.form.get('pay_date') or '').strip())
        period_start = _parse_date((request.form.get('period_start') or '').strip())
        period_end = _parse_date((request.form.get('period_end') or '').strip())

        if not pay_date:
            pay_date = pl.pay_date or datetime.date.today()

        hours_raw = (request.form.get('hours') or '').strip()
        regular_gross_raw = (request.form.get('regular_gross') or '').strip()

        hours = float(pl.hours or 0.0)
        if hours_raw:
            try:
                hours = float(hours_raw)
            except Exception:
                flash('Hours must be a number.', 'danger')
                return redirect(url_for('owner_edit_payroll_line', payroll_line_id=pl.id, next=next_url))
        if hours < 0:
            flash('Hours cannot be negative.', 'danger')
            return redirect(url_for('owner_edit_payroll_line', payroll_line_id=pl.id, next=next_url))

        regular_gross = None
        if regular_gross_raw:
            try:
                regular_gross = float(regular_gross_raw)
            except Exception:
                flash('Gross (before vacation pay) must be a number.', 'danger')
                return redirect(url_for('owner_edit_payroll_line', payroll_line_id=pl.id, next=next_url))

        if regular_gross is None:
            if employee and hours and float(employee.pay_rate or 0.0) > 0:
                regular_gross = float(hours) * float(employee.pay_rate or 0.0)
            else:
                existing_regular = float(pl.gross or 0.0) - float(pl.vacation_pay or 0.0)
                regular_gross = max(0.0, existing_regular)

        if regular_gross < 0:
            flash('Gross (before vacation pay) cannot be negative.', 'danger')
            return redirect(url_for('owner_edit_payroll_line', payroll_line_id=pl.id, next=next_url))

        pl.pay_date = pay_date
        pl.period_start = period_start
        pl.period_end = period_end
        pl.hours = float(hours)

        vacation_pay = 0.0
        if employee and bool(getattr(employee, 'vacation_pay_enabled', False)):
            vacation_pay = 0.04 * float(regular_gross or 0.0)
        pl.vacation_pay = float(vacation_pay or 0.0)
        pl.gross = float(regular_gross or 0.0) + float(vacation_pay or 0.0)

        _recalculate_employee_payroll_lines(pl.employee_id)
        db.session.commit()

        flash('Payroll line updated.', 'success')
        return redirect(next_url)

    regular_gross = float(pl.gross or 0.0) - float(pl.vacation_pay or 0.0)
    if regular_gross < 0:
        regular_gross = float(pl.gross or 0.0)

    return render_template(
        'owner_edit_payroll_line.html',
        pl=pl,
        employee=employee,
        regular_gross=round(float(regular_gross or 0.0), 2),
        next_url=next_url,
        next_url_encoded=next_url_encoded,
    )


@app.route('/owner/payroll/line/<int:payroll_line_id>/delete', methods=['POST'])
@require_login
def owner_delete_payroll_line(payroll_line_id: int):
    if not _is_owner_session():
        abort(403)

    pl = db.session.get(PayrollLine, payroll_line_id)
    if not pl:
        abort(404)

    employee = db.session.get(Employee, pl.employee_id) if pl.employee_id else None
    if not employee or employee.company_id != session.get('company_id'):
        abort(403)

    employee_id = pl.employee_id
    PayrollSubmission.query.filter(PayrollSubmission.payroll_line_id == pl.id).delete(synchronize_session=False)
    db.session.delete(pl)
    db.session.flush()
    _recalculate_employee_payroll_lines(employee_id)
    db.session.commit()

    flash('Payroll line deleted.', 'success')
    next_url = (request.args.get('next') or '').strip() or url_for('owner_payroll_edit')
    return redirect(next_url)


@app.route('/owner/payroll-summary', methods=['GET'])
@require_login
def owner_payroll_summary():
    if not _is_owner_session():
        abort(403)

    company_id = session.get('company_id')
    if not company_id:
        abort(403)

    date_from_raw = (request.args.get('date_from') or '').strip()
    date_to_raw = (request.args.get('date_to') or '').strip()

    date_from = None
    date_to = None
    if date_from_raw:
        try:
            date_from = datetime.date.fromisoformat(date_from_raw)
        except Exception:
            flash('From date must be a valid date.', 'danger')
            return redirect(url_for('owner_payroll_summary'))

    if date_to_raw:
        try:
            date_to = datetime.date.fromisoformat(date_to_raw)
        except Exception:
            flash('To date must be a valid date.', 'danger')
            return redirect(url_for('owner_payroll_summary'))

    if date_from and date_to and date_from > date_to:
        flash('From date cannot be after To date.', 'danger')
        return redirect(url_for('owner_payroll_summary'))

    show_results = bool(date_from and date_to)
    sum_gross = sum_income_tax = sum_ei_emp = sum_ei_employer = 0.0
    sum_cpp_base = sum_cpp2 = sum_cpp2_employer = 0.0
    total_tax_amount = 0.0

    if show_results:
        q = (
            db.session.query(
                func.coalesce(func.sum(PayrollLine.gross), 0.0),
                func.coalesce(func.sum(PayrollLine.federal_tax), 0.0),
                func.coalesce(func.sum(PayrollLine.ontario_tax), 0.0),
                func.coalesce(func.sum(PayrollLine.ei_employee), 0.0),
                func.coalesce(func.sum(PayrollLine.ei_employer), 0.0),
                func.coalesce(func.sum(PayrollLine.cpp_employee), 0.0),
                func.coalesce(func.sum(PayrollLine.cpp2_employee), 0.0),
                func.coalesce(func.sum(PayrollLine.cpp2_employer), 0.0),
            )
            .join(Employee)
            .filter(Employee.company_id == int(company_id))
            .filter(PayrollLine.pay_date >= date_from)
            .filter(PayrollLine.pay_date <= date_to)
        )

        (
            sum_gross,
            sum_federal,
            sum_ontario,
            sum_ei_emp,
            sum_ei_employer,
            sum_cpp_total,
            sum_cpp2,
            sum_cpp2_employer,
        ) = q.one()

        sum_income_tax = float(sum_federal or 0.0) + float(sum_ontario or 0.0)
        sum_cpp_base = max(0.0, float(sum_cpp_total or 0.0) - float(sum_cpp2 or 0.0))

        total_tax_amount = (
            sum_income_tax
            + float(sum_ei_emp or 0.0)
            + float(sum_ei_employer or 0.0)
            + float(sum_cpp_base or 0.0)
            + float(sum_cpp_base or 0.0)
            + float(sum_cpp2 or 0.0)
            + float(sum_cpp2_employer or 0.0)
        )

    rows = [
        {
            'label': 'Income Tax',
            'total_wages': sum_gross if show_results else None,
            'excess_wages': 0.0 if show_results else None,
            'taxable_wages': sum_gross if show_results else None,
            'tax_amount': sum_income_tax if show_results else None,
        },
        {
            'label': 'Employment Insurance',
            'total_wages': sum_gross if show_results else None,
            'excess_wages': 0.0 if show_results else None,
            'taxable_wages': sum_gross if show_results else None,
            'tax_amount': sum_ei_emp if show_results else None,
        },
        {
            'label': 'Employment Insurance Employer',
            'total_wages': sum_gross if show_results else None,
            'excess_wages': 0.0 if show_results else None,
            'taxable_wages': sum_gross if show_results else None,
            'tax_amount': sum_ei_employer if show_results else None,
        },
        {
            'label': 'Canada Pension Plan',
            'total_wages': sum_gross if show_results else None,
            'excess_wages': 0.0 if show_results else None,
            'taxable_wages': sum_gross if show_results else None,
            'tax_amount': sum_cpp_base if show_results else None,
        },
        {
            'label': 'Canada Pension Plan Employer',
            'total_wages': sum_gross if show_results else None,
            'excess_wages': 0.0 if show_results else None,
            'taxable_wages': sum_gross if show_results else None,
            'tax_amount': sum_cpp_base if show_results else None,
        },
        {
            'label': 'Second Canada Pension Plan',
            'total_wages': sum_gross if show_results else None,
            'excess_wages': 0.0 if show_results else None,
            'taxable_wages': sum_gross if show_results else None,
            'tax_amount': sum_cpp2 if show_results else None,
        },
        {
            'label': 'Second Canada Pension Plan Employer',
            'total_wages': sum_gross if show_results else None,
            'excess_wages': 0.0 if show_results else None,
            'taxable_wages': sum_gross if show_results else None,
            'tax_amount': sum_cpp2_employer if show_results else None,
        },
    ]

    return render_template(
        'owner_payroll_summary.html',
        rows=rows,
        total_tax_amount=total_tax_amount,
        show_results=show_results,
        selected_date_from=date_from_raw,
        selected_date_to=date_to_raw,
    )


@app.route('/admin/submissions', methods=['GET'])
@require_admin
def admin_submissions():
    submissions = (
        PayrollSubmission.query
        .join(Employee)
        .order_by(PayrollSubmission.status.asc(), PayrollSubmission.created_at.desc(), PayrollSubmission.id.desc())
        .limit(300)
        .all()
    )
    return render_template('admin_submissions.html', submissions=submissions)


@app.route('/admin/users', methods=['GET'])
@require_admin
def admin_users():
    companies = Company.query.order_by(Company.name).all()
    company_id = (request.args.get('company_id') or '').strip()

    q = User.query
    if company_id:
        try:
            q = q.filter(User.company_id == int(company_id))
        except Exception:
            q = q

    users = q.order_by(User.role.asc(), User.username.asc()).all()

    return render_template(
        'admin_users.html',
        users=users,
        companies=companies,
        selected_company_id=company_id,
    )


@app.route('/admin/users/<int:user_id>/reset', methods=['POST'])
@require_admin
def admin_user_reset(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)

    new_password = (request.form.get('new_password') or '').strip()
    if not new_password:
        flash('New password is required.', 'danger')
        return redirect(url_for('admin_users'))

    user.set_password(new_password)
    db.session.commit()
    flash('Password updated.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:user_id>/toggle', methods=['POST'])
@require_admin
def admin_user_toggle(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)

    current_admin_id = session.get('user_id')
    if current_admin_id and int(current_admin_id) == int(user.id):
        flash('You cannot change your own account status.', 'danger')
        return redirect(url_for('admin_users'))

    user.is_active = not bool(getattr(user, 'is_active', True))
    db.session.commit()
    flash('User status updated.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/submissions/<int:submission_id>/process', methods=['POST'])
@require_admin
def admin_process_submission(submission_id: int):
    sub = db.session.get(PayrollSubmission, submission_id)
    if not sub:
        abort(404)

    if (sub.status or '') == 'processed' and sub.payroll_line_id:
        flash('Submission already processed.', 'info')
        return redirect(url_for('admin_submissions'))

    employee = db.session.get(Employee, sub.employee_id)
    if not employee:
        flash('Employee not found for submission.', 'danger')
        return redirect(url_for('admin_submissions'))

    hours = float(sub.hours or 0.0)
    pay_rate = float(employee.pay_rate or 0.0)
    regular_gross = hours * pay_rate
    vacation_pay = 0.0
    if bool(getattr(employee, 'vacation_pay_enabled', False)):
        vacation_pay = 0.04 * float(regular_gross or 0.0)
    gross = float(regular_gross or 0.0) + float(vacation_pay or 0.0)

    pay_periods = _pay_periods_from_employee(employee)

    pay_date = sub.pay_date
    year_start = datetime.date(pay_date.year, 1, 1)
    year_end = datetime.date(pay_date.year, 12, 31)
    ytd_filter = [
        PayrollLine.employee_id == employee.id,
        PayrollLine.pay_date >= year_start,
        PayrollLine.pay_date <= year_end,
        PayrollLine.pay_date < pay_date,
    ]

    ytd_cpp = float(
        db.session.query(func.coalesce(func.sum(PayrollLine.cpp_employee), 0.0))
        .filter(*ytd_filter)
        .scalar()
        or 0.0
    )
    ytd_cpp2 = float(
        db.session.query(func.coalesce(func.sum(PayrollLine.cpp2_employee), 0.0))
        .filter(*ytd_filter)
        .scalar()
        or 0.0
    )
    ytd_ei_emp = float(
        db.session.query(func.coalesce(func.sum(PayrollLine.ei_employee), 0.0))
        .filter(*ytd_filter)
        .scalar()
        or 0.0
    )
    ytd_ei_employer = float(
        db.session.query(func.coalesce(func.sum(PayrollLine.ei_employer), 0.0))
        .filter(*ytd_filter)
        .scalar()
        or 0.0
    )

    result = calculate_payroll(
        gross,
        pay_periods_per_year=pay_periods,
        ytd_cpp_employee=ytd_cpp,
        ytd_cpp2_employee=ytd_cpp2,
        ytd_ei_employee=ytd_ei_emp,
        ytd_ei_employer=ytd_ei_employer,
        ei_exempt=bool(getattr(employee, 'ei_exempt', False)),
    )

    pl = PayrollLine(
        employee_id=employee.id,
        hours=hours,
        vacation_pay=float(vacation_pay or 0.0),
        gross=float(result['gross']),
        net=float(result['net_pay']),
        cpp_employee=float(result['cpp_employee']),
        cpp2_employee=float(result.get('cpp2_employee', 0.0)),
        ei_employee=float(result['ei_employee']),
        ei_employer=float(result['ei_employer']),
        cpp2_employer=float(result.get('cpp2_employer', 0.0)),
        federal_tax=float(result['federal_tax']),
        ontario_tax=float(result['ontario_tax']),
        total_employee_deductions=float(result['total_employee_deductions']),
        employer_total_cost=float(result['employer_total_cost']),
        total_remittance=float(result['total_remittance']),
        period_start=sub.period_start,
        period_end=sub.period_end,
        pay_date=pay_date,
    )
    db.session.add(pl)
    db.session.flush()

    sub.status = 'processed'
    sub.payroll_line_id = pl.id
    sub.processed_at = datetime.datetime.utcnow()

    _recalculate_employee_payroll_lines(employee.id)
    db.session.commit()

    flash('Submission processed and paystub published.', 'success')
    return redirect(url_for('admin_submissions'))


def _pay_periods_from_employee(employee: Employee) -> int:
    pay_periods = 26
    if employee and employee.payroll_frequency:
        freq = (employee.payroll_frequency or '').strip().lower()
        if freq == 'weekly':
            pay_periods = 52
        elif freq in {'bi-weekly', 'biweekly'}:
            pay_periods = 26
        elif freq == 'monthly':
            pay_periods = 12
    return pay_periods


def _recalculate_employee_payroll_lines(employee_id: int) -> None:
    """Recalculate all payroll lines for an employee in chronological order.

    This keeps CPP/CPP2/EI annual maxima consistent when a pay date or gross changes.
    """
    employee = db.session.get(Employee, employee_id)
    if not employee:
        return

    lines = (
        PayrollLine.query.filter(PayrollLine.employee_id == employee_id)
        .order_by(PayrollLine.pay_date.asc(), PayrollLine.id.asc())
        .all()
    )

    pay_periods = _pay_periods_from_employee(employee)

    ytd_cpp = 0.0
    ytd_cpp2 = 0.0
    ytd_ei_emp = 0.0
    ytd_ei_employer = 0.0
    current_year = None

    for pl in lines:
        if not pl.pay_date:
            # Treat missing pay dates as the oldest entries.
            pl_year = None
        else:
            pl_year = pl.pay_date.year

        if pl_year != current_year:
            current_year = pl_year
            ytd_cpp = 0.0
            ytd_cpp2 = 0.0
            ytd_ei_emp = 0.0
            ytd_ei_employer = 0.0

        # Preserve the saved gross amount; only recompute deductions based on it.
        gross = float(pl.gross or 0.0)

        result = calculate_payroll(
            gross,
            pay_periods_per_year=pay_periods,
            ytd_cpp_employee=ytd_cpp,
            ytd_cpp2_employee=ytd_cpp2,
            ytd_ei_employee=ytd_ei_emp,
            ytd_ei_employer=ytd_ei_employer,
            ei_exempt=bool(getattr(employee, 'ei_exempt', False)),
        )

        pl.gross = float(result['gross'])
        pl.net = float(result['net_pay'])
        pl.cpp_employee = float(result['cpp_employee'])
        pl.cpp2_employee = float(result.get('cpp2_employee', 0.0))
        pl.ei_employee = float(result['ei_employee'])
        pl.ei_employer = float(result['ei_employer'])
        pl.cpp2_employer = float(result.get('cpp2_employer', 0.0))
        pl.federal_tax = float(result['federal_tax'])
        pl.ontario_tax = float(result['ontario_tax'])
        pl.total_employee_deductions = float(result['total_employee_deductions'])
        pl.employer_total_cost = float(result['employer_total_cost'])
        pl.total_remittance = float(result['total_remittance'])

        ytd_cpp += float(result['cpp_employee'] or 0.0)
        ytd_cpp2 += float(result.get('cpp2_employee', 0.0) or 0.0)
        ytd_ei_emp += float(result['ei_employee'] or 0.0)
        ytd_ei_employer += float(result['ei_employer'] or 0.0)


@app.route('/payroll/<int:payroll_line_id>/edit', methods=['GET', 'POST'])
@require_admin
def edit_payroll_line(payroll_line_id):
    pl = db.session.get(PayrollLine, payroll_line_id)
    if not pl:
        abort(404)
    employee = db.session.get(Employee, pl.employee_id) if pl.employee_id else None

    def _parse_date(s):
        if not s:
            return None
        try:
            return datetime.date.fromisoformat(s)
        except Exception:
            return None

    next_url = (request.args.get('next') or '').strip() or url_for('manage_data')
    next_url_encoded = quote(next_url, safe='')

    if request.method == 'POST':
        pay_date = _parse_date((request.form.get('pay_date') or '').strip())
        period_start = _parse_date((request.form.get('period_start') or '').strip())
        period_end = _parse_date((request.form.get('period_end') or '').strip())

        if not pay_date:
            pay_date = pl.pay_date or datetime.date.today()

        hours_raw = (request.form.get('hours') or '').strip()
        regular_gross_raw = (request.form.get('regular_gross') or '').strip()

        hours = float(pl.hours or 0.0)
        if hours_raw:
            try:
                hours = float(hours_raw)
            except Exception:
                flash('Hours must be a number.', 'danger')
                return redirect(url_for('edit_payroll_line', payroll_line_id=pl.id, next=next_url))
        if hours < 0:
            flash('Hours cannot be negative.', 'danger')
            return redirect(url_for('edit_payroll_line', payroll_line_id=pl.id, next=next_url))

        regular_gross = None
        if regular_gross_raw:
            try:
                regular_gross = float(regular_gross_raw)
            except Exception:
                flash('Gross (before vacation pay) must be a number.', 'danger')
                return redirect(url_for('edit_payroll_line', payroll_line_id=pl.id, next=next_url))

        if regular_gross is None:
            # If gross is not entered, derive from hours × current employee pay rate.
            if employee and hours and float(employee.pay_rate or 0.0) > 0:
                regular_gross = float(hours) * float(employee.pay_rate or 0.0)
            else:
                # Fall back to existing value (gross - vacation pay)
                existing_regular = float(pl.gross or 0.0) - float(pl.vacation_pay or 0.0)
                regular_gross = max(0.0, existing_regular)

        if regular_gross < 0:
            flash('Gross (before vacation pay) cannot be negative.', 'danger')
            return redirect(url_for('edit_payroll_line', payroll_line_id=pl.id, next=next_url))

        pl.pay_date = pay_date
        pl.period_start = period_start
        pl.period_end = period_end
        pl.hours = float(hours)

        vacation_pay = 0.0
        if employee and bool(getattr(employee, 'vacation_pay_enabled', False)):
            vacation_pay = 0.04 * float(regular_gross or 0.0)
        pl.vacation_pay = float(vacation_pay or 0.0)
        pl.gross = float(regular_gross or 0.0) + float(vacation_pay or 0.0)

        # Recalculate this employee's payroll lines so annual/YTD caps stay consistent.
        _recalculate_employee_payroll_lines(pl.employee_id)
        db.session.commit()

        flash('Payroll line updated.', 'success')
        return redirect(next_url)

    regular_gross = float(pl.gross or 0.0) - float(pl.vacation_pay or 0.0)
    if regular_gross < 0:
        regular_gross = float(pl.gross or 0.0)

    return render_template(
        'edit_payroll_line.html',
        pl=pl,
        employee=employee,
        regular_gross=round(float(regular_gross or 0.0), 2),
        next_url=next_url,
        next_url_encoded=next_url_encoded,
    )


@app.route('/payroll/<int:payroll_line_id>/delete', methods=['POST'])
@require_admin
def delete_payroll_line(payroll_line_id):
    pl = db.session.get(PayrollLine, payroll_line_id)
    if not pl:
        abort(404)
    PayrollSubmission.query.filter(PayrollSubmission.payroll_line_id == pl.id).delete(synchronize_session=False)
    db.session.delete(pl)
    db.session.commit()
    flash('Payroll line deleted.', 'success')
    return redirect(url_for('manage_data'))


@app.route('/reports', methods=['GET', 'POST'])
@require_admin
def reports():
    companies = Company.query.all()
    employees = []
    company_reports = None
    remittance = None
    employee_report = None
    selected_company_id = request.form.get('company_id') if request.method == 'POST' else ''
    selected_employee_id = request.form.get('employee_id') if request.method == 'POST' else ''
    selected_date_from = request.form.get('date_from') if request.method == 'POST' else ''
    selected_date_to = request.form.get('date_to') if request.method == 'POST' else ''

    if selected_company_id:
        try:
            employees = (
                Employee.query
                .filter(Employee.company_id == int(selected_company_id))
                .order_by(Employee.first_name, Employee.last_name)
                .all()
            )
        except Exception:
            employees = []

    def _parse_date(s):
        if not s:
            return None
        try:
            return datetime.date.fromisoformat(s)
        except Exception:
            return None

    if request.method == 'POST':
        company_id = request.form.get('company_id')
        employee_id = request.form.get('employee_id')
        date_from = request.form.get('date_from')
        date_to = request.form.get('date_to')

        company = db.session.get(Company, int(company_id)) if company_id else None
        employee = db.session.get(Employee, int(employee_id)) if employee_id else None
        if employee and company and int(employee.company_id or 0) != int(company.id):
            flash('Selected employee does not belong to the selected company.', 'danger')
            return render_template(
                'reports.html',
                companies=companies,
                employees=employees,
                company_reports=company_reports,
                remittance=remittance,
                employee_report=employee_report,
                selected_company_id=selected_company_id,
                selected_employee_id=selected_employee_id,
                selected_date_from=selected_date_from,
                selected_date_to=selected_date_to,
            )
        date_from_d = _parse_date(date_from)
        date_to_d = _parse_date(date_to)

        # Category 1: Company + Dates => Remittance summary
        if company and date_from_d and date_to_d and not employee:
            q = PayrollLine.query.join(Employee).filter(Employee.company_id == company.id)
            q = q.filter(PayrollLine.pay_date >= date_from_d, PayrollLine.pay_date <= date_to_d)

            total_gross = float(
                db.session.query(func.coalesce(func.sum(PayrollLine.gross), 0.0))
                .select_from(PayrollLine)
                .join(Employee)
                .filter(Employee.company_id == company.id)
                .filter(PayrollLine.pay_date >= date_from_d, PayrollLine.pay_date <= date_to_d)
                .scalar()
                or 0.0
            )
            total_remittance = float(
                db.session.query(func.coalesce(func.sum(PayrollLine.total_remittance), 0.0))
                .select_from(PayrollLine)
                .join(Employee)
                .filter(Employee.company_id == company.id)
                .filter(PayrollLine.pay_date >= date_from_d, PayrollLine.pay_date <= date_to_d)
                .scalar()
                or 0.0
            )
            num_employees = int(
                db.session.query(func.count(func.distinct(PayrollLine.employee_id)))
                .select_from(PayrollLine)
                .join(Employee)
                .filter(Employee.company_id == company.id)
                .filter(PayrollLine.pay_date >= date_from_d, PayrollLine.pay_date <= date_to_d)
                .scalar()
                or 0
            )

            bn = (company.business_number or '').strip()
            payroll_account_number = f"{bn} RP 0001".strip() if bn else "RP 0001"

            remittance = {
                'company_name': company.name,
                'company_address': company.address or '',
                'payroll_account_number': payroll_account_number,
                'num_employees': num_employees,
                'total_gross': total_gross,
                'total_remittance': total_remittance,
                'date_from': date_from_d,
                'date_to': date_to_d,
            }

        # Category 2: Company + Employee + Dates => Paystubs and ROE options
        if company and employee and date_from_d and date_to_d:
            employee_report = {
                'company': company,
                'employee': employee,
                'date_from': date_from_d,
                'date_to': date_to_d,
            }

        q = (
            db.session.query(
                Company.id.label('company_id'),
                Company.name.label('company_name'),
                func.coalesce(func.sum(PayrollLine.gross), 0.0).label('total_gross'),
                func.coalesce(func.sum(PayrollLine.total_remittance), 0.0).label('total_remit'),
                func.coalesce(func.sum(PayrollLine.employer_total_cost), 0.0).label('total_employer_cost'),
            )
            .join(Employee, Employee.company_id == Company.id)
            .join(PayrollLine, PayrollLine.employee_id == Employee.id)
        )

        if company_id:
            q = q.filter(Company.id == int(company_id))
        if employee_id:
            q = q.filter(Employee.id == int(employee_id))
        if date_from:
            q = q.filter(PayrollLine.pay_date >= date_from)
        if date_to:
            q = q.filter(PayrollLine.pay_date <= date_to)

        q = q.group_by(Company.id).order_by(Company.name)
        company_reports = q.all()

    return render_template(
        'reports.html',
        company_reports=company_reports,
        remittance=remittance,
        employee_report=employee_report,
        companies=companies,
        employees=employees,
        selected_company_id=selected_company_id,
        selected_employee_id=selected_employee_id,
        selected_date_from=selected_date_from,
        selected_date_to=selected_date_to,
    )


@app.route('/admin/maintenance/migrate_subcontract_bills', methods=['GET'])
@require_admin
def migrate_subcontract_bills():
    _ensure_subcontract_bill_columns()
    flash('Subcontract bill columns migration attempted. Refresh the page.', 'success')
    return redirect(url_for('reports'))


def _generate_paystubs_pdf(lines: list[PayrollLine]) -> bytes:
    # Paystub PDF generator (ReportLab) styled to match the provided template
    import io
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    company_name_style = ParagraphStyle('CompanyName', parent=styles['Normal'], fontSize=11, leading=13, alignment=TA_LEFT)
    header_value = ParagraphStyle('HeaderValue', parent=styles['Normal'], fontSize=10, alignment=TA_LEFT, leading=12)
    header_value_right = ParagraphStyle('HeaderValueRight', parent=styles['Normal'], fontSize=10, alignment=TA_RIGHT, leading=12)
    section_label = ParagraphStyle('SectionLabel', parent=styles['Normal'], fontSize=10, alignment=TA_LEFT, leading=12)
    section_value = ParagraphStyle('SectionValue', parent=styles['Normal'], fontSize=10, alignment=TA_LEFT, leading=12)
    number_style = ParagraphStyle('Number', parent=styles['Normal'], fontSize=10, alignment=TA_RIGHT, leading=12)
    number_bold = ParagraphStyle('NumberBold', parent=styles['Normal'], fontSize=11, alignment=TA_RIGHT, leading=13)
    header_num = ParagraphStyle('HeaderNum', parent=styles['Normal'], fontSize=10, alignment=TA_RIGHT, leading=12)
    net_pay_label_style = ParagraphStyle('NetPayLabel', parent=styles['Normal'], fontSize=12, alignment=TA_RIGHT, leading=14)
    net_pay_amount_style = ParagraphStyle('NetPayAmount', parent=styles['Normal'], fontSize=13, alignment=TA_RIGHT, leading=15)
    title_style = ParagraphStyle('PaystubTitle', parent=styles['Normal'], fontSize=12, alignment=TA_CENTER, leading=14)
    elements = []

    def _fmt_date(d):
        if not d:
            return ''
        try:
            return d.strftime('%d-%m-%Y')
        except Exception:
            return str(d)

    def _money(v):
        try:
            return f"${float(v or 0.0):,.2f}"
        except Exception:
            return "$0.00"

    def _format_company_address(address: str) -> list[str]:
        """Format address as: street line, city+province line, postal code line."""
        if not address:
            return []
        raw = str(address).replace('\r', '\n')
        parts = [p.strip() for p in raw.split('\n') if p.strip()]
        if len(parts) >= 3:
            street = parts[0]
            city_prov = parts[1].replace('  ', ' ').strip()
            postal = parts[2]
            return [street, city_prov, postal]

        # Try comma-separated: "street, City, ON, POSTAL" or similar
        tokens = [t.strip() for t in raw.replace('\n', ',').split(',') if t.strip()]
        if len(tokens) >= 4:
            street = tokens[0]
            city = tokens[1]
            prov = tokens[2]
            postal = tokens[3]
            return [street, f"{city}, {prov}", postal]
        if len(tokens) == 3:
            street = tokens[0]
            city_prov = tokens[1]
            postal = tokens[2]
            return [street, city_prov, postal]
        return [tokens[0]] if tokens else []

    def _as_template_addr_two_lines(address: str) -> list[str]:
        """Template prefers: street on one line, then city/prov/postal on one line."""
        lines = _format_company_address(address)
        if not lines:
            return []
        if len(lines) >= 3:
            return [lines[0], f"{lines[1]} {lines[2]}".replace('  ', ' ').strip()]
        if len(lines) == 2:
            return lines
        return [lines[0]]

    if not lines:
        elements.append(Paragraph('No payroll lines match the filters.', styles['Normal']))
    else:
        for idx, pl in enumerate(lines):
            emp = pl.employee
            comp = emp.company
            display_name = (comp.name if comp and comp.name else 'Employer').strip() or 'Employer'
            display_address = (comp.address if comp and comp.address else '').strip()
            address_lines = _as_template_addr_two_lines(display_address)

            employee_name = (f"{emp.first_name} {emp.last_name}").strip()
            employee_address = (emp.address or '').strip()
            employee_addr_lines = _as_template_addr_two_lines(employee_address)

            pay_date = pl.pay_date or datetime.date.today()
            period_start = pl.period_start
            period_end = pl.period_end

            try:
                year = pl.pay_date.year if pl.pay_date else datetime.date.today().year
            except Exception:
                year = datetime.date.today().year
            ytd_start = datetime.date(year, 1, 1)
            def _sum_field(field):
                s = db.session.query(func.coalesce(func.sum(field), 0)).filter(PayrollLine.employee_id == emp.id)
                s = s.filter(PayrollLine.pay_date >= ytd_start)
                if pl.pay_date:
                    s = s.filter(PayrollLine.pay_date <= pl.pay_date)
                return float(s.scalar() or 0.0)

            ytd_gross = _sum_field(PayrollLine.gross)
            ytd_vacation_pay = _sum_field(PayrollLine.vacation_pay)
            ytd_cpp = _sum_field(PayrollLine.cpp_employee)
            ytd_cpp2 = _sum_field(PayrollLine.cpp2_employee)
            ytd_ei = _sum_field(PayrollLine.ei_employee)
            ytd_fed = _sum_field(PayrollLine.federal_tax)
            ytd_ont = _sum_field(PayrollLine.ontario_tax)
            ytd_taxes = ytd_fed + ytd_ont
            ytd_total_deductions = _sum_field(PayrollLine.total_employee_deductions)

            hours = float(pl.hours or 0.0)
            pay_rate = float(emp.pay_rate or 0.0)

            vacation_pay_current = float(getattr(pl, 'vacation_pay', 0.0) or 0.0)
            regular_pay_current = float(pl.gross or 0.0) - vacation_pay_current
            ytd_regular_pay = float(ytd_gross or 0.0) - float(ytd_vacation_pay or 0.0)

            cpp = float(pl.cpp_employee or 0.0)
            cpp2 = float(pl.cpp2_employee or 0.0)
            ei = float(pl.ei_employee or 0.0)
            income_tax = float((pl.federal_tax or 0.0) + (pl.ontario_tax or 0.0))
            taxes_current = cpp + cpp2 + ei + income_tax
            taxes_ytd = float(ytd_cpp + ytd_cpp2 + ytd_ei + ytd_taxes)

            net_pay = float(pl.net or 0.0)

            # Title: centered at the top
            elements.append(Paragraph('Earning Statement', title_style))
            elements.append(Spacer(1, 0.12 * inch))

            # Header: EMPLOYER (left) + PAY PERIOD (right)
            employer_block = [
                Paragraph('<b>EMPLOYER</b>', section_label),
                Paragraph(display_name, section_value),
            ]
            for line in address_lines:
                employer_block.append(Paragraph(line, section_value))

            pay_period_table = Table(
                [
                    [Paragraph('<b>PAY PERIOD</b>', section_label), '', ''],
                    [Paragraph('Period Beginning', section_value), '', Paragraph(_fmt_date(period_start), header_value_right)],
                    [Paragraph('Period Ending:', section_value), '', Paragraph(_fmt_date(period_end), header_value_right)],
                    [Paragraph('Pay Date:', section_value), '', Paragraph(_fmt_date(pay_date), header_value_right)],
                ],
                colWidths=[1.8 * inch, 0.2 * inch, 1.2 * inch],
            )
            pay_period_table.setStyle(TableStyle([
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                ('TOPPADDING', (0, 0), (-1, -1), 0),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
                ('SPAN', (0, 0), (2, 0)),
            ]))

            header_tbl = Table([[employer_block, pay_period_table]], colWidths=[doc.width * 0.60, doc.width * 0.40])
            header_tbl.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ]))
            elements.append(header_tbl)
            elements.append(Spacer(1, 0.20 * inch))

            # Employee block
            elements.append(Paragraph('<b>EMPLOYEE</b>', section_label))
            elements.append(Paragraph(employee_name, section_value))
            for line in employee_addr_lines:
                elements.append(Paragraph(line, section_value))
            elements.append(Spacer(1, 0.24 * inch))

            # Combined PAY / DEDUCTIONS table (mirrors template)
            pay_ded_rows = [
                [
                    Paragraph('<b>PAY</b>', section_label),
                    Paragraph('<b>Hours</b>', header_num),
                    Paragraph('<b>Rate</b>', header_num),
                    Paragraph('<b>Current</b>', header_num),
                    Paragraph('<b>YTD</b>', header_num),
                    Paragraph('<b>DEDUCTIONS</b>', section_label),
                    Paragraph('<b>Current</b>', header_num),
                    Paragraph('<b>YTD</b>', header_num),
                ],
                [
                    Paragraph('Regular Pay', section_value),
                    Paragraph(f"{hours:,.2f}", number_style),
                    Paragraph(f"{pay_rate:,.2f}", number_style),
                    Paragraph(f"{regular_pay_current:,.2f}", number_style),
                    Paragraph(f"{ytd_regular_pay:,.2f}", number_style),
                    Paragraph('&nbsp;', section_value),
                    Paragraph('0.00', number_style),
                    Paragraph('0.00', number_style),
                ],
                [
                    Paragraph('Vacation Pay', section_value),
                    Paragraph('-', number_style),
                    Paragraph('-', number_style),
                    Paragraph(f"{vacation_pay_current:,.2f}", number_style),
                    Paragraph(f"{ytd_vacation_pay:,.2f}", number_style),
                    Paragraph('&nbsp;', section_value),
                    Paragraph('0.00', number_style),
                    Paragraph('0.00', number_style),
                ],
            ]
            avail_w = doc.width
            # Scale columns to full page width (no outline box)
            raw_widths = [1.60, 0.55, 0.55, 0.80, 0.80, 1.20, 0.75, 0.75]
            scale = avail_w / (sum(raw_widths) * inch)
            col_widths = [(w * inch) * scale for w in raw_widths]
            pay_ded_tbl = Table(pay_ded_rows, colWidths=col_widths)
            pay_ded_tbl.setStyle(TableStyle([
                ('LINEABOVE', (0, 0), (-1, 0), 0.5, colors.black),
                ('LINEBELOW', (0, 0), (-1, 0), 0.5, colors.black),
                ('ALIGN', (1, 1), (4, -1), 'RIGHT'),
                ('ALIGN', (6, 1), (7, -1), 'RIGHT'),
                ('ALIGN', (1, 0), (4, 0), 'RIGHT'),
                ('ALIGN', (6, 0), (7, 0), 'RIGHT'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(pay_ded_tbl)
            elements.append(Spacer(1, 0.10 * inch))

            # Bottom area: TAXES (left) + SUMMARY boxed (right), then Net Pay line below
            left_col_w = doc.width * 0.55
            right_col_w = doc.width * 0.45

            taxes_rows = [
                [Paragraph('<b>TAXES</b>', section_label), Paragraph('<b>Current</b>', header_num), Paragraph('<b>YTD</b>', header_num)],
                [Paragraph('Income Tax', section_value), Paragraph(f"{income_tax:,.2f}", number_style), Paragraph(f"{ytd_taxes:,.2f}", number_style)],
                [Paragraph('Employment Insurance', section_value), Paragraph(f"{ei:,.2f}", number_style), Paragraph(f"{ytd_ei:,.2f}", number_style)],
                [Paragraph('Canada Pension Plan', section_value), Paragraph(f"{cpp:,.2f}", number_style), Paragraph(f"{ytd_cpp:,.2f}", number_style)],
                [Paragraph('Second Canada Pension Plan', section_value), Paragraph(f"{cpp2:,.2f}", number_style), Paragraph(f"{ytd_cpp2:,.2f}", number_style)],
            ]
            taxes_tbl = Table(taxes_rows, colWidths=[2.6 * inch, 0.7 * inch, 0.7 * inch])
            taxes_tbl.setStyle(TableStyle([
                ('LINEBELOW', (0, 0), (-1, 0), 0.5, colors.black),
                ('ALIGN', (1, 1), (-1, -1), 'RIGHT'),
                ('ALIGN', (1, 0), (-1, 0), 'RIGHT'),
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                ('TOPPADDING', (0, 0), (-1, -1), 1),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
            ]))

            summary_rows = [
                [Paragraph('<b>SUMMARY</b>', section_label), Paragraph('<b>Current</b>', header_num), Paragraph('<b>YTD</b>', header_num)],
                [Paragraph('Total Pay', section_value), Paragraph(_money(pl.gross or 0.0), number_style), Paragraph(_money(ytd_gross), number_style)],
                [Paragraph('Taxes', section_value), Paragraph(_money(taxes_current), number_style), Paragraph(_money(taxes_ytd), number_style)],
                [Paragraph('Deductions', section_value), Paragraph(_money(0.0), number_style), Paragraph(_money(0.0), number_style)],
            ]
            summary_tbl = Table(summary_rows, colWidths=[1.6 * inch, 0.8 * inch, 0.8 * inch])
            summary_tbl.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 0.5, colors.black),
                ('LINEBELOW', (0, 0), (-1, 0), 0.5, colors.black),
                ('ALIGN', (1, 1), (-1, -1), 'RIGHT'),
                ('ALIGN', (1, 0), (-1, 0), 'RIGHT'),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ]))

            bottom_tbl = Table([[taxes_tbl, summary_tbl]], colWidths=[doc.width * 0.55, doc.width * 0.45])
            bottom_tbl.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ]))
            elements.append(bottom_tbl)
            elements.append(Spacer(1, 0.10 * inch))

            # Final Net Pay: boxed callout, slightly larger text
            # Match Summary width (1.6 + 0.8 + 0.8 = 3.2 inch)
            net_box = Table(
                [[
                    Paragraph('<b>Net Pay</b>', net_pay_label_style),
                    Paragraph(f"<b>{_money(net_pay)}</b>", net_pay_amount_style),
                ]],
                colWidths=[1.6 * inch, 1.6 * inch],
            )
            net_box.setStyle(TableStyle([
                ('BOX', (0, 0), (-1, -1), 0.75, colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'RIGHT'),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))
            net_box_wrap = Table([['', net_box]], colWidths=[doc.width * 0.55, doc.width * 0.45])
            net_box_wrap.setStyle(TableStyle([
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(net_box_wrap)

            if idx != len(lines) - 1:
                elements.append(PageBreak())

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()


@app.route('/paystubs/<int:payroll_line_id>/pdf', methods=['GET'])
@require_login
def paystub_pdf(payroll_line_id: int):
    pl = db.session.get(PayrollLine, payroll_line_id)
    if not pl:
        abort(404)

    if _is_owner_session():
        company_id = session.get('company_id')
        if not company_id:
            abort(403)
        if not pl.employee or pl.employee.company_id != int(company_id):
            abort(403)
        published = PayrollSubmission.query.filter(
            PayrollSubmission.company_id == int(company_id),
            PayrollSubmission.payroll_line_id == pl.id,
            PayrollSubmission.status == 'processed',
        ).first()
        if not published:
            abort(403)

    data = _generate_paystubs_pdf([pl])
    return (data, 200, {
        'Content-Type': 'application/pdf',
        'Content-Disposition': f'attachment; filename="paystub_{pl.id}.pdf"'
    })


@app.route('/reports/paystubs_pdf', methods=['GET', 'POST'])
@require_admin
def reports_paystubs_pdf():
    form = request.form if request.method == 'POST' else request.args
    company_id = form.get('company_id')
    employee_id = form.get('employee_id')
    date_from = form.get('date_from')
    date_to = form.get('date_to')

    q = PayrollLine.query.join(Employee)
    if company_id:
        q = q.filter(Employee.company_id == int(company_id))
    if employee_id:
        q = q.filter(PayrollLine.employee_id == int(employee_id))
    if date_from:
        q = q.filter(PayrollLine.pay_date >= date_from)
    if date_to:
        q = q.filter(PayrollLine.pay_date <= date_to)

    # If a date range/filter is provided, generate all matching paystubs.
    # Otherwise, default to ONE paystub per PDF (most recent match).
    if date_from or date_to:
        lines = q.order_by(PayrollLine.pay_date.asc(), PayrollLine.id.asc()).all()
    else:
        pl_latest = q.order_by(PayrollLine.pay_date.desc(), PayrollLine.id.desc()).first()
        lines = [pl_latest] if pl_latest else []

    data = _generate_paystubs_pdf(lines)
    return (data, 200, {
        'Content-Type': 'application/pdf',
        'Content-Disposition': 'attachment; filename="paystubs.pdf"'
    })

@app.route('/reports/paystubs_preview', methods=['GET', 'POST'])
@require_admin
def reports_paystubs_preview():
    # reuse generator but return inline for browser preview
    resp = reports_paystubs_pdf()
    data, status, headers = resp
    headers['Content-Disposition'] = 'inline; filename="paystubs_preview.pdf"'
    return (data, status, headers)


@app.route('/reports/paystubs_preview_page', methods=['POST'])
@require_admin
def reports_paystubs_preview_page():
    # HTML wrapper to show explicit Print/Download controls
    company_id = request.form.get('company_id') or ''
    employee_id = request.form.get('employee_id') or ''
    date_from = request.form.get('date_from') or ''
    date_to = request.form.get('date_to') or ''

    pdf_preview_url = url_for(
        'reports_paystubs_preview',
        company_id=company_id,
        employee_id=employee_id,
        date_from=date_from,
        date_to=date_to,
    )
    pdf_download_url = url_for(
        'reports_paystubs_pdf',
        company_id=company_id,
        employee_id=employee_id,
        date_from=date_from,
        date_to=date_to,
    )
    return render_template(
        'pdf_preview.html',
        title='Paystubs Preview',
        pdf_url=pdf_preview_url,
        download_url=pdf_download_url,
    )


@app.route('/owner/paystubs_pdf', methods=['GET'])
@require_login
def owner_paystubs_pdf():
    if not _is_owner_session():
        abort(403)

    company_id = session.get('company_id')
    if not company_id:
        abort(403)

    pay_date = (request.args.get('pay_date') or '').strip()
    period_start = (request.args.get('period_start') or '').strip()
    period_end = (request.args.get('period_end') or '').strip()
    date_from = (request.args.get('date_from') or '').strip()
    date_to = (request.args.get('date_to') or '').strip()
    employee_id = (request.args.get('employee_id') or '').strip()

    q = PayrollLine.query.join(Employee).filter(Employee.company_id == int(company_id))
    if employee_id:
        try:
            q = q.filter(PayrollLine.employee_id == int(employee_id))
        except Exception:
            q = q
    if pay_date:
        q = q.filter(PayrollLine.pay_date == pay_date)
    if period_start:
        q = q.filter(PayrollLine.period_start == period_start)
    if period_end:
        q = q.filter(PayrollLine.period_end == period_end)
    if date_from:
        q = q.filter(PayrollLine.pay_date >= date_from)
    if date_to:
        q = q.filter(PayrollLine.pay_date <= date_to)

    lines = q.order_by(PayrollLine.pay_date.asc(), PayrollLine.id.asc()).all()
    data = _generate_paystubs_pdf(lines)
    return (data, 200, {
        'Content-Type': 'application/pdf',
        'Content-Disposition': 'attachment; filename="paystubs.pdf"'
    })


@app.route('/owner/paystubs_preview', methods=['GET'])
@require_login
def owner_paystubs_preview():
    if not _is_owner_session():
        abort(403)

    resp = owner_paystubs_pdf()
    data, status, headers = resp
    headers['Content-Disposition'] = 'inline; filename="paystubs_preview.pdf"'
    return (data, status, headers)


@app.route('/owner/reports', methods=['GET'])
@require_login
def owner_reports():
    if not _is_owner_session():
        abort(403)

    company_id = session.get('company_id')
    if not company_id:
        abort(403)

    company_id_int = int(company_id)
    employees = (
        Employee.query.filter(Employee.company_id == company_id_int)
        .order_by(Employee.first_name, Employee.last_name)
        .all()
    )

    run = (request.args.get('run') or '').strip()
    employee_id = (request.args.get('employee_id') or '').strip()
    date_from = (request.args.get('date_from') or '').strip()
    date_to = (request.args.get('date_to') or '').strip()

    lines = []
    if run == '1':
        q = PayrollLine.query.join(Employee).filter(Employee.company_id == company_id_int)
        if employee_id:
            try:
                q = q.filter(PayrollLine.employee_id == int(employee_id))
            except Exception:
                q = q
        if date_from:
            q = q.filter(PayrollLine.pay_date >= date_from)
        if date_to:
            q = q.filter(PayrollLine.pay_date <= date_to)

        lines = q.order_by(PayrollLine.pay_date.desc(), PayrollLine.id.desc()).limit(200).all()

    return render_template(
        'owner_reports.html',
        employees=employees,
        lines=lines,
        selected_employee_id=employee_id,
        selected_date_from=date_from,
        selected_date_to=date_to,
        run=run,
    )


@app.route('/reports/roe_pdf', methods=['GET', 'POST'])
@require_admin
def reports_roe_pdf():
    # ROE generation: use a tabular layout for multiple entries
    import io
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.enums import TA_LEFT, TA_RIGHT

    form = request.form if request.method == 'POST' else request.args
    company_id = form.get('company_id')
    employee_id = form.get('employee_id')
    date_from = form.get('date_from')
    date_to = form.get('date_to')
    q = PayrollLine.query.join(Employee)
    if company_id:
        q = q.filter(Employee.company_id == int(company_id))
    if employee_id:
        q = q.filter(PayrollLine.employee_id == int(employee_id))
    if date_from:
        q = q.filter(PayrollLine.pay_date >= date_from)
    if date_to:
        q = q.filter(PayrollLine.pay_date <= date_to)
    lines = q.order_by(PayrollLine.pay_date).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    elements = []

    header_label = styles['Normal'].clone('header_label')
    header_label.fontSize = 9
    header_label.leading = 11
    header_label.alignment = TA_LEFT

    header_value = styles['Normal'].clone('header_value')
    header_value.fontSize = 9
    header_value.leading = 11
    header_value.alignment = TA_LEFT

    header_value_right = styles['Normal'].clone('header_value_right')
    header_value_right.fontSize = 9
    header_value_right.leading = 11
    header_value_right.alignment = TA_RIGHT

    if len(lines) == 1:
        emp = lines[0].employee
        comp = emp.company if emp else None
    elif len(lines) > 1:
        emp = lines[0].employee
        comp = emp.company if emp else None
    else:
        emp = None
        comp = None

    if not lines:
        elements.append(Paragraph('No payroll lines match the filters.', styles['Normal']))
    else:
        company_name = (comp.name if comp and comp.name else 'Company').strip() or 'Company'
        company_address = (comp.address if comp and comp.address else '').strip()
        company_bn = (comp.business_number if comp and comp.business_number else '').strip()

        employee_name = (f"{emp.first_name} {emp.last_name}" if emp else 'Employee').strip()
        employee_address = (emp.address or '').strip() if emp else ''
        employee_sin = (emp.sin or '').strip() if emp else ''

        left_block = [
            Paragraph('<b>EMPLOYER</b>', header_label),
            Paragraph(company_name, header_value),
        ]
        if company_address:
            for line in str(company_address).replace('\r', '\n').split('\n'):
                line = line.strip()
                if line:
                    left_block.append(Paragraph(line, header_value))
        if company_bn:
            left_block.append(Paragraph(f"Business Number: {company_bn}", header_value))

        right_block = [
            Paragraph('<b>EMPLOYEE</b>', header_label),
            Paragraph(employee_name, header_value_right),
        ]
        if employee_address:
            for line in str(employee_address).replace('\r', '\n').split('\n'):
                line = line.strip()
                if line:
                    right_block.append(Paragraph(line, header_value_right))
        if employee_sin:
            right_block.append(Paragraph(f"SIN: {employee_sin}", header_value_right))

        header_tbl = Table([[left_block, right_block]], colWidths=[doc.width * 0.55, doc.width * 0.45])
        header_tbl.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ]))
        elements.append(header_tbl)
        elements.append(Spacer(1, 0.15 * inch))

        data = [[
            'Pay Date',
            'Total Income',
            'CPP (Emp)',
            'EI (Emp)',
            'Taxes',
            'CPP (Empr)',
            'EI (Empr)',
            'Deductions',
        ]]
        for pl in lines:
            taxes = float(pl.federal_tax or 0.0) + float(pl.ontario_tax or 0.0)
            deductions = float(pl.total_employee_deductions or 0.0)
            data.append([
                str(pl.pay_date) if pl.pay_date else '',
                f"${pl.gross:,.2f}",
                f"${float(pl.cpp_employee or 0.0):,.2f}",
                f"${float(pl.ei_employee or 0.0):,.2f}",
                f"${taxes:,.2f}",
                f"${float(pl.cpp2_employer or 0.0) + float(pl.cpp_employee or 0.0):,.2f}",
                f"${float(pl.ei_employer or 0.0):,.2f}",
                f"${deductions:,.2f}",
            ])

        table = Table(
            data,
            colWidths=[1.0*inch, 1.1*inch, 0.95*inch, 0.95*inch, 0.9*inch, 1.0*inch, 0.95*inch, 1.0*inch]
        )
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
            ('ALIGN', (1, 1), (-1, -1), 'RIGHT'),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ]))
        elements.append(table)

    doc.build(elements)
    buffer.seek(0)
    return (buffer.getvalue(), 200, {
        'Content-Type': 'application/pdf',
        'Content-Disposition': 'attachment; filename="roe.pdf"'
    })


@app.route('/reports/roe_preview', methods=['GET', 'POST'])
@require_admin
def reports_roe_preview():
    resp = reports_roe_pdf()
    data, status, headers = resp
    headers['Content-Disposition'] = 'inline; filename="roe_preview.pdf"'
    return (data, status, headers)


@app.route('/reports/roe_preview_page', methods=['POST'])
@require_admin
def reports_roe_preview_page():
    company_id = request.form.get('company_id') or ''
    employee_id = request.form.get('employee_id') or ''
    date_from = request.form.get('date_from') or ''
    date_to = request.form.get('date_to') or ''

    pdf_preview_url = url_for(
        'reports_roe_preview',
        company_id=company_id,
        employee_id=employee_id,
        date_from=date_from,
        date_to=date_to,
    )
    pdf_download_url = url_for(
        'reports_roe_pdf',
        company_id=company_id,
        employee_id=employee_id,
        date_from=date_from,
        date_to=date_to,
    )
    return render_template(
        'pdf_preview.html',
        title='ROE Preview',
        pdf_url=pdf_preview_url,
        download_url=pdf_download_url,
    )


def _compute_remittance(company_id: int, date_from_d: datetime.date, date_to_d: datetime.date):
    company = db.session.get(Company, int(company_id)) if company_id else None
    if not company or not date_from_d or not date_to_d:
        return None

    def _format_bn_display(bn_raw: str) -> str:
        bn_raw = (bn_raw or '').strip()
        digits = ''.join(ch for ch in bn_raw if ch.isdigit())
        if len(digits) == 9:
            return f"{digits[:5]} {digits[5:]}"
        return bn_raw

    total_gross = float(
        db.session.query(func.coalesce(func.sum(PayrollLine.gross), 0.0))
        .select_from(PayrollLine)
        .join(Employee)
        .filter(Employee.company_id == company.id)
        .filter(PayrollLine.pay_date >= date_from_d, PayrollLine.pay_date <= date_to_d)
        .scalar()
        or 0.0
    )
    total_remittance = float(
        db.session.query(func.coalesce(func.sum(PayrollLine.total_remittance), 0.0))
        .select_from(PayrollLine)
        .join(Employee)
        .filter(Employee.company_id == company.id)
        .filter(PayrollLine.pay_date >= date_from_d, PayrollLine.pay_date <= date_to_d)
        .scalar()
        or 0.0
    )
    num_employees = int(
        db.session.query(func.count(func.distinct(PayrollLine.employee_id)))
        .select_from(PayrollLine)
        .join(Employee)
        .filter(Employee.company_id == company.id)
        .filter(PayrollLine.pay_date >= date_from_d, PayrollLine.pay_date <= date_to_d)
        .scalar()
        or 0
    )

    # Employees in last pay period within selected range
    last_pay_date = (
        db.session.query(func.max(PayrollLine.pay_date))
        .select_from(PayrollLine)
        .join(Employee)
        .filter(Employee.company_id == company.id)
        .filter(PayrollLine.pay_date >= date_from_d, PayrollLine.pay_date <= date_to_d)
        .scalar()
    )
    num_employees_last_pay_period = 0
    if last_pay_date:
        num_employees_last_pay_period = int(
            db.session.query(func.count(func.distinct(PayrollLine.employee_id)))
            .select_from(PayrollLine)
            .join(Employee)
            .filter(Employee.company_id == company.id)
            .filter(PayrollLine.pay_date == last_pay_date)
            .scalar()
            or 0
        )

    bn_raw = (company.business_number or '').strip()
    bn_display = _format_bn_display(bn_raw)
    payroll_account_number = f"{bn_display} RP0001".strip() if bn_display else "RP0001"

    def _format_address_three_lines(address: str) -> list[str]:
        """Best-effort split into: street, city+province, postal."""
        if not address:
            return []
        raw = str(address).replace('\r', '\n')
        lines = [ln.strip() for ln in raw.split('\n') if ln.strip()]
        if len(lines) >= 3:
            return [lines[0], lines[1], lines[2]]
        # Try comma-separated: street, city, province, postal
        tokens = [t.strip() for t in raw.replace('\n', ',').split(',') if t.strip()]
        if len(tokens) >= 4:
            street = tokens[0]
            city = tokens[1]
            prov = tokens[2]
            postal = tokens[3]
            return [street, f"{city} {prov}".replace('  ', ' ').strip(), postal]
        if len(tokens) == 3:
            street = tokens[0]
            city_prov = tokens[1]
            postal = tokens[2]
            return [street, city_prov, postal]
        if len(lines) == 2:
            return [lines[0], lines[1]]
        return [lines[0]] if lines else []

    address_lines = _format_address_three_lines(company.address or '')

    return {
        'company': company,
        'company_name': company.name,
        'company_address': company.address or '',
        'company_address_lines': address_lines,
        'payroll_account_number': payroll_account_number,
        'num_employees': num_employees,
        'num_employees_last_pay_period': num_employees_last_pay_period,
        'last_pay_date': last_pay_date,
        'bn_display': bn_display,
        'total_gross': total_gross,
        'total_remittance': total_remittance,
        'date_from': date_from_d,
        'date_to': date_to_d,
    }


def _compute_company_summary(company_id: int, date_from_d: datetime.date, date_to_d: datetime.date):
    company = db.session.get(Company, int(company_id)) if company_id else None
    if not company or not date_from_d or not date_to_d:
        return None

    rows = (
        db.session.query(
            Employee.id.label('employee_id'),
            Employee.first_name.label('first_name'),
            Employee.last_name.label('last_name'),
            func.coalesce(func.sum(PayrollLine.gross), 0.0).label('gross'),
            func.coalesce(func.sum(PayrollLine.cpp_employee), 0.0).label('e_cpp'),
            func.coalesce(func.sum(PayrollLine.cpp2_employee), 0.0).label('e_cpp2'),
            func.coalesce(func.sum(PayrollLine.ei_employee), 0.0).label('e_ei'),
            func.coalesce(func.sum(PayrollLine.federal_tax), 0.0).label('fed'),
            func.coalesce(func.sum(PayrollLine.ontario_tax), 0.0).label('prov'),
            func.coalesce(func.sum(PayrollLine.ei_employer), 0.0).label('c_ei'),
            func.coalesce(func.sum(PayrollLine.cpp2_employer), 0.0).label('c_cpp2'),
            func.coalesce(func.sum(PayrollLine.total_remittance), 0.0).label('deductions'),
        )
        .join(PayrollLine, PayrollLine.employee_id == Employee.id)
        .filter(Employee.company_id == company.id)
        .filter(PayrollLine.pay_date >= date_from_d, PayrollLine.pay_date <= date_to_d)
        .group_by(Employee.id)
        .order_by(Employee.first_name, Employee.last_name)
        .all()
    )

    table_rows = []
    totals = {
        'gross': 0.0,
        'e_cpp': 0.0,
        'e_ei': 0.0,
        'fed': 0.0,
        'prov': 0.0,
        'c_cpp': 0.0,
        'c_ei': 0.0,
        'deductions': 0.0,
    }

    for r in rows:
        name = (f"{r.first_name or ''} {r.last_name or ''}").strip() or 'Employee'
        e_cpp_total = float(r.e_cpp or 0.0) + float(r.e_cpp2 or 0.0)
        c_cpp_total = float(r.e_cpp or 0.0) + float(r.c_cpp2 or 0.0)
        row_obj = {
            'name': name,
            'gross': float(r.gross or 0.0),
            'e_cpp': e_cpp_total,
            'e_ei': float(r.e_ei or 0.0),
            'fed': float(r.fed or 0.0),
            'prov': float(r.prov or 0.0),
            'c_cpp': c_cpp_total,
            'c_ei': float(r.c_ei or 0.0),
            'deductions': float(r.deductions or 0.0),
        }
        table_rows.append(row_obj)
        for k in totals:
            totals[k] += float(row_obj[k] or 0.0)

    bn = (company.business_number or '').strip()
    return {
        'company': company,
        'company_name': company.name,
        'business_number': bn,
        'date_from': date_from_d,
        'date_to': date_to_d,
        'rows': table_rows,
        'totals': totals,
    }


@app.route('/reports/summary_preview', methods=['GET', 'POST'])
@require_admin
def reports_summary_preview():
    form = request.form if request.method == 'POST' else request.args
    company_id = form.get('company_id')
    date_from = form.get('date_from')
    date_to = form.get('date_to')

    def _parse_date(s):
        if not s:
            return None
        try:
            return datetime.date.fromisoformat(s)
        except Exception:
            return None

    date_from_d = _parse_date(date_from)
    date_to_d = _parse_date(date_to)
    summary = _compute_company_summary(int(company_id) if company_id else None, date_from_d, date_to_d)
    if not summary:
        abort(400)

    download_url = url_for('reports_summary_pdf', company_id=company_id, date_from=date_from, date_to=date_to)
    return render_template('summary_preview.html', summary=summary, download_url=download_url)


@app.route('/reports/summary_pdf', methods=['GET'])
@require_admin
def reports_summary_pdf():
    import io
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors

    company_id = request.args.get('company_id')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    def _parse_date(s):
        if not s:
            return None
        try:
            return datetime.date.fromisoformat(s)
        except Exception:
            return None

    date_from_d = _parse_date(date_from)
    date_to_d = _parse_date(date_to)
    summary = _compute_company_summary(int(company_id) if company_id else None, date_from_d, date_to_d)
    if not summary:
        abort(400)

    def _money(v):
        try:
            return f"${float(v or 0.0):,.2f}"
        except Exception:
            return "$0.00"

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph('Company Summary', styles['Title']))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(f"Company Name: {summary['company_name']}", styles['Normal']))
    elements.append(Paragraph(f"Business Number: {summary['business_number']}", styles['Normal']))
    elements.append(Paragraph(f"Start: {summary['date_from']}", styles['Normal']))
    elements.append(Paragraph(f"End: {summary['date_to']}", styles['Normal']))
    elements.append(Spacer(1, 10))

    header = ['Name', 'GROSS', 'E CPP', 'E EI', 'FED', 'PROV', 'C CPP', 'C EI', 'DEDUCTIONS']
    data = [header]
    for r in summary['rows']:
        data.append([
            r['name'],
            _money(r['gross']),
            _money(r['e_cpp']),
            _money(r['e_ei']),
            _money(r['fed']),
            _money(r['prov']),
            _money(r['c_cpp']),
            _money(r['c_ei']),
            _money(r['deductions']),
        ])
    t = summary['totals']
    data.append([
        'TOTAL',
        _money(t['gross']),
        _money(t['e_cpp']),
        _money(t['e_ei']),
        _money(t['fed']),
        _money(t['prov']),
        _money(t['c_cpp']),
        _money(t['c_ei']),
        _money(t['deductions']),
    ])

    tbl = Table(data, repeatRows=1)
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
        ('ALIGN', (1, 1), (-1, -1), 'RIGHT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),
    ]))
    elements.append(tbl)

    doc.build(elements)
    buffer.seek(0)
    return (buffer.getvalue(), 200, {
        'Content-Type': 'application/pdf',
        'Content-Disposition': 'attachment; filename="summary.pdf"'
    })


@app.route('/reports/remittance_preview', methods=['GET', 'POST'])
@require_admin
def reports_remittance_preview():
    form = request.form if request.method == 'POST' else request.args
    company_id = form.get('company_id')
    date_from = form.get('date_from')
    date_to = form.get('date_to')

    def _parse_date(s):
        if not s:
            return None
        try:
            return datetime.date.fromisoformat(s)
        except Exception:
            return None

    date_from_d = _parse_date(date_from)
    date_to_d = _parse_date(date_to)
    remittance = _compute_remittance(int(company_id) if company_id else None, date_from_d, date_to_d)
    if not remittance:
        abort(400)

    print_url = url_for(
        'reports_remittance_print',
        company_id=company_id,
        date_from=date_from,
        date_to=date_to,
    )
    download_url = url_for(
        'reports_remittance_download',
        company_id=company_id,
        date_from=date_from,
        date_to=date_to,
    )
    return render_template('remittance_preview.html', remittance=remittance, download_url=download_url, print_url=print_url, auto_print=False)


@app.route('/reports/remittance_download', methods=['GET', 'POST'])
@require_admin
def reports_remittance_download():
    # HTML "download" page that prints exactly like the preview (users can Save as PDF).
    form = request.form if request.method == 'POST' else request.args
    company_id = form.get('company_id')
    date_from = form.get('date_from')
    date_to = form.get('date_to')

    def _parse_date(s):
        if not s:
            return None
        try:
            return datetime.date.fromisoformat(s)
        except Exception:
            return None

    date_from_d = _parse_date(date_from)
    date_to_d = _parse_date(date_to)
    remittance = _compute_remittance(int(company_id) if company_id else None, date_from_d, date_to_d)
    if not remittance:
        abort(400)

    # Voucher-only page; auto-open print dialog so user can "Save as PDF".
    return render_template('remittance_print.html', remittance=remittance, auto_print=True)


@app.route('/reports/remittance_print', methods=['GET'])
@require_admin
def reports_remittance_print():
    company_id = request.args.get('company_id')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    def _parse_date(s):
        if not s:
            return None
        try:
            return datetime.date.fromisoformat(s)
        except Exception:
            return None

    date_from_d = _parse_date(date_from)
    date_to_d = _parse_date(date_to)
    remittance = _compute_remittance(int(company_id) if company_id else None, date_from_d, date_to_d)
    if not remittance:
        abort(400)

    return render_template('remittance_print.html', remittance=remittance, auto_print=True)


@app.route('/reports/remittance_pdf', methods=['GET'])
@require_admin
def reports_remittance_pdf():
    import io
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors

    company_id = request.args.get('company_id')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    def _parse_date(s):
        if not s:
            return None
        try:
            return datetime.date.fromisoformat(s)
        except Exception:
            return None

    date_from_d = _parse_date(date_from)
    date_to_d = _parse_date(date_to)
    remittance = _compute_remittance(int(company_id) if company_id else None, date_from_d, date_to_d)
    if not remittance:
        abort(400)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph('Remittance Summary', styles['Title']))
    elements.append(Spacer(1, 12))

    def _money(v):
        try:
            return f"${float(v or 0.0):,.2f}"
        except Exception:
            return "$0.00"

    meta = [
        ['Company Name', remittance['company_name']],
        ['Address', remittance['company_address']],
        ['Payroll Account Number', remittance['payroll_account_number']],
        ['Period', f"{remittance['date_from']} to {remittance['date_to']}"],
    ]
    meta_tbl = Table(meta, colWidths=[170, 360])
    meta_tbl.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
        ('BACKGROUND', (0, 0), (0, -1), colors.whitesmoke),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(meta_tbl)
    elements.append(Spacer(1, 12))

    totals = [
        ['Employees (Selected Period)', str(remittance['num_employees'])],
        ['Total Gross Payroll', _money(remittance['total_gross'])],
        ['Total Remittance to CRA', _money(remittance['total_remittance'])],
    ]
    totals_tbl = Table(totals, colWidths=[250, 280])
    totals_tbl.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
        ('BACKGROUND', (0, 0), (0, -1), colors.whitesmoke),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(totals_tbl)

    doc.build(elements)
    buffer.seek(0)
    return (buffer.getvalue(), 200, {
        'Content-Type': 'application/pdf',
        'Content-Disposition': 'attachment; filename="remittance.pdf"'
    })


# Debug helper: quick GET preview for paystubs (returns inline PDF)
@app.route('/debug/paystubs_preview_demo', methods=['GET'])
def debug_paystubs_preview_demo():
    # Reuse existing generator which reads request.form; empty form is fine
    resp = reports_paystubs_pdf()
    # reports_paystubs_pdf returns (data, status, headers)
    if isinstance(resp, tuple):
        data, status, headers = resp
        headers['Content-Disposition'] = 'inline; filename="paystubs_demo.pdf"'
        return (data, status, headers)
    # If a Flask Response object is returned, adjust headers and return
    resp.headers['Content-Disposition'] = 'inline; filename="paystubs_demo.pdf"'
    return resp


if __name__ == '__main__':
    app.run(debug=True)
