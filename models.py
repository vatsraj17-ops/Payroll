from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    address = db.Column(db.String(256), nullable=True)
    business_number = db.Column(db.String(20), nullable=True)
    logo_filename = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(64), nullable=False)
    last_name = db.Column(db.String(64), nullable=False)
    address = db.Column(db.String(256), nullable=True)
    sin = db.Column(db.String(16), nullable=True)
    hire_date = db.Column(db.Date, nullable=True)
    payroll_frequency = db.Column(db.String(32), nullable=True)
    pay_rate = db.Column(db.Float, default=0.0)
    vacation_pay_enabled = db.Column(db.Boolean, default=False)
    ei_exempt = db.Column(db.Boolean, default=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    annual_salary = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    company = db.relationship('Company', backref=db.backref('employees', lazy=True))
    payroll_lines = db.relationship('PayrollLine', backref='employee', lazy=True)


class PayrollRun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    period_start = db.Column(db.Date)
    period_end = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PayrollLine(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    payroll_run_id = db.Column(db.Integer, db.ForeignKey('payroll_run.id'))
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    hours = db.Column(db.Float, default=0.0)
    vacation_pay = db.Column(db.Float, default=0.0)
    gross = db.Column(db.Float, default=0.0)
    net = db.Column(db.Float, default=0.0)
    cpp_employee = db.Column(db.Float, default=0.0)
    cpp2_employee = db.Column(db.Float, default=0.0)
    ei_employee = db.Column(db.Float, default=0.0)
    ei_employer = db.Column(db.Float, default=0.0)
    cpp2_employer = db.Column(db.Float, default=0.0)
    federal_tax = db.Column(db.Float, default=0.0)
    ontario_tax = db.Column(db.Float, default=0.0)
    total_employee_deductions = db.Column(db.Float, default=0.0)
    employer_total_cost = db.Column(db.Float, default=0.0)
    total_remittance = db.Column(db.Float, default=0.0)
    period_start = db.Column(db.Date, nullable=True)
    period_end = db.Column(db.Date, nullable=True)
    pay_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(16), nullable=False, default='owner')  # 'admin' | 'owner'
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    company = db.relationship('Company', backref=db.backref('users', lazy=True))

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class PayrollSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    period_start = db.Column(db.Date, nullable=True)
    period_end = db.Column(db.Date, nullable=True)
    pay_date = db.Column(db.Date, nullable=False)
    hours = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(16), nullable=False, default='submitted')  # submitted|processed
    payroll_line_id = db.Column(db.Integer, db.ForeignKey('payroll_line.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime, nullable=True)

    company = db.relationship('Company', backref=db.backref('payroll_submissions', lazy=True))
    employee = db.relationship('Employee', backref=db.backref('payroll_submissions', lazy=True))
    payroll_line = db.relationship('PayrollLine', backref=db.backref('submission', uselist=False))
