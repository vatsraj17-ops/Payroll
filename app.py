from flask import Flask, render_template, request, redirect, url_for, send_file, abort, flash, session
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
import os
import datetime
from flask_sqlalchemy import SQLAlchemy
from models import db, Company, Employee, PayrollLine, User, PayrollSubmission
from calc import calculate_payroll
from sqlalchemy import func
import random
from urllib.parse import quote
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
if (os.environ.get('FLASK_ENV') or '').lower() == 'production' or (os.environ.get('ENV') or '').lower() == 'production':
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = True

db.init_app(app)


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
            return redirect(url_for('login', next=request.full_path))
        if not _is_admin_session():
            abort(403)
        return view_func(*args, **kwargs)
    return _wrapped


def require_login(view_func):
    @wraps(view_func)
    def _wrapped(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for('login', next=request.full_path))
        return view_func(*args, **kwargs)
    return _wrapped


@app.before_request
def _require_login():
    # Allow login page and static assets without authentication.
    if request.endpoint in {'login', 'static'}:
        return None
    if request.path.startswith('/static/'):
        return None
    if not is_logged_in():
        return redirect(url_for('login', next=request.full_path))
    return None


@app.route('/login', methods=['GET', 'POST'])
def login():
    next_url = (request.args.get('next') or '').strip() or '/'
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = (request.form.get('password') or '').strip()

        user = User.query.filter(func.lower(User.username) == username.lower()).first()
        if user and user.check_password(password):
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
    db.create_all()

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
    if _is_owner_session() and session.get('company_id'):
        try:
            c = db.session.get(Company, int(session.get('company_id')))
            if c and c.name:
                company_name = c.name
        except Exception:
            company_name = ''
    elif _is_admin_session():
        company_name = 'Admin'
    return render_template('index.html', company_name=company_name)


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


@app.route('/employees', methods=['GET', 'POST'])
@require_login
def employees():
    if _is_admin_session():
        companies = Company.query.all()
    else:
        cid = session.get('company_id')
        companies = Company.query.filter(Company.id == int(cid)).all() if cid else []
    if request.method == 'POST':
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

    employees_for_dropdown = Employee.query
    if company_id:
        try:
            employees_for_dropdown = employees_for_dropdown.filter(Employee.company_id == int(company_id))
        except Exception:
            employees_for_dropdown = employees_for_dropdown
    employees_for_dropdown = employees_for_dropdown.order_by(Employee.first_name, Employee.last_name).all()

    employees = []
    if run == '1':
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
    )


@app.route('/employees/<int:employee_id>/delete', methods=['POST'])
@require_login
def delete_employee(employee_id):
    e = db.session.get(Employee, employee_id)
    if not e:
        abort(404)
    _require_employee_access(e)
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
    employees = Employee.query.all()
    result = None
    if request.method == 'POST':
        action = (request.form.get('action') or 'preview').strip().lower()
        emp_id = request.form.get('employee_id')
        hours_raw = (request.form.get('total_hours') or '').strip()
        gross_raw = (request.form.get('gross') or '').strip()
        employee = db.session.get(Employee, int(emp_id)) if emp_id else None

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
    return render_template('data_entry.html', companies=companies, employees=employees, result=result, mode='submit')


@app.route('/manage/data', methods=['GET'])
@require_admin
def manage_data():
    companies = Company.query.order_by(Company.name).all()
    employees = Employee.query.order_by(Employee.first_name, Employee.last_name).all()

    run = (request.args.get('run') or '').strip()

    company_id = (request.args.get('company_id') or '').strip()
    employee_id = (request.args.get('employee_id') or '').strip()
    date_from = (request.args.get('date_from') or '').strip()
    date_to = (request.args.get('date_to') or '').strip()

    lines = []
    if run == '1':
        q = PayrollLine.query.join(Employee)
        if company_id:
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
        employee_id_raw = (request.form.get('employee_id') or '').strip()
        period_start_raw = (request.form.get('period_start') or '').strip()
        period_end_raw = (request.form.get('period_end') or '').strip()
        pay_date_raw = (request.form.get('pay_date') or '').strip()
        hours_raw = (request.form.get('hours') or '').strip()

        if not employee_id_raw:
            flash('Employee is required.', 'danger')
            return redirect(url_for('owner_payroll'))

        try:
            employee_id = int(employee_id_raw)
        except Exception:
            flash('Employee selection is invalid.', 'danger')
            return redirect(url_for('owner_payroll'))

        employee = db.session.get(Employee, employee_id)
        if not employee or employee.company_id != company_id_int:
            abort(403)

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

        try:
            hours = float(hours_raw)
        except Exception:
            flash('Hours must be a number.', 'danger')
            return redirect(url_for('owner_payroll'))

        if hours < 0:
            flash('Hours cannot be negative.', 'danger')
            return redirect(url_for('owner_payroll'))

        sub = PayrollSubmission(
            company_id=company_id_int,
            employee_id=employee.id,
            period_start=period_start,
            period_end=period_end,
            pay_date=pay_date,
            hours=hours,
            status='submitted',
        )
        db.session.add(sub)
        db.session.commit()
        flash('Payroll submission sent.', 'success')
        return redirect(url_for('owner_payroll'))

    submissions = (
        PayrollSubmission.query
        .filter(PayrollSubmission.company_id == company_id_int)
        .join(Employee)
        .order_by(PayrollSubmission.created_at.desc(), PayrollSubmission.id.desc())
        .limit(200)
        .all()
    )

    return render_template('owner_payroll.html', employees=employees, submissions=submissions)


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
    db.session.delete(pl)
    db.session.commit()
    flash('Payroll line deleted.', 'success')
    return redirect(url_for('manage_data'))


@app.route('/reports', methods=['GET', 'POST'])
@require_admin
def reports():
    companies = Company.query.all()
    employees = Employee.query.all()
    company_reports = None
    remittance = None
    employee_report = None
    selected_company_id = request.form.get('company_id') if request.method == 'POST' else ''
    selected_employee_id = request.form.get('employee_id') if request.method == 'POST' else ''
    selected_date_from = request.form.get('date_from') if request.method == 'POST' else ''
    selected_date_to = request.form.get('date_to') if request.method == 'POST' else ''

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


def _generate_paystubs_pdf(lines: list[PayrollLine]) -> bytes:
    # Paystub PDF generator (ReportLab) styled to match the provided template
    import io
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_RIGHT

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    company_name_style = ParagraphStyle('CompanyName', parent=styles['Normal'], fontSize=10, leading=12, alignment=TA_LEFT)
    header_value = ParagraphStyle('HeaderValue', parent=styles['Normal'], fontSize=9, alignment=TA_LEFT, leading=11)
    header_value_right = ParagraphStyle('HeaderValueRight', parent=styles['Normal'], fontSize=9, alignment=TA_RIGHT, leading=11)
    section_label = ParagraphStyle('SectionLabel', parent=styles['Normal'], fontSize=9, alignment=TA_LEFT, leading=11)
    section_value = ParagraphStyle('SectionValue', parent=styles['Normal'], fontSize=9, alignment=TA_LEFT, leading=11)
    number_style = ParagraphStyle('Number', parent=styles['Normal'], fontSize=9, alignment=TA_RIGHT, leading=11)
    number_bold = ParagraphStyle('NumberBold', parent=styles['Normal'], fontSize=10, alignment=TA_RIGHT, leading=12)
    header_num = ParagraphStyle('HeaderNum', parent=styles['Normal'], fontSize=9, alignment=TA_RIGHT, leading=11)
    net_pay_label_style = ParagraphStyle('NetPayLabel', parent=styles['Normal'], fontSize=11, alignment=TA_RIGHT, leading=13)
    net_pay_amount_style = ParagraphStyle('NetPayAmount', parent=styles['Normal'], fontSize=12, alignment=TA_RIGHT, leading=14)
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

    elements.append(Paragraph('Record of Employment (ROE) - Report', styles['Title']))
    elements.append(Spacer(1, 0.1 * inch))

    data = [['Employee', 'SIN', 'Hire Date', 'Period Start', 'Period End', 'Pay Date', 'Gross', 'Net']]
    for pl in lines:
        emp = pl.employee
        data.append([
            f"{emp.first_name} {emp.last_name}",
            emp.sin or '',
            str(emp.hire_date) if emp.hire_date else '',
            str(pl.period_start) if pl.period_start else '',
            str(pl.period_end) if pl.period_end else '',
            str(pl.pay_date) if pl.pay_date else '',
            f"${pl.gross:,.2f}",
            f"${pl.net:,.2f}",
        ])

    if len(data) == 1:
        elements.append(Paragraph('No payroll lines match the filters.', styles['Normal']))
    else:
        # include Total Remittance column in ROE
        # add header for Total Remittance and include value per payroll line
        data[0].append('Total Remittance')
        for i in range(1, len(data)):
            # append total_remittance for each row (index aligns with lines order)
            # rows were built in same order as 'lines'
            # compute index into lines: i-1
            pl_row = lines[i-1]
            data[i].append(f"${pl_row.total_remittance:,.2f}")
        table = Table(data, colWidths=[1.4*inch, 1*inch, 0.9*inch, 0.9*inch, 0.9*inch, 0.9*inch, 0.9*inch, 0.9*inch, 0.9*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('GRID', (0,0), (-1,-1), 0.25, colors.grey),
            ('ALIGN', (6,1), (7,-1), 'RIGHT'),
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
