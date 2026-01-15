import os
import sys

# ensure project root on path for imports
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app import app, reports_paystubs_pdf
from models import db, Company, Employee, PayrollLine
from calc import calculate_payroll
import datetime

OUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'output')
os.makedirs(OUT_DIR, exist_ok=True)
OUT_PATH = os.path.join(OUT_DIR, 'paystubs_preview.pdf')

with app.app_context():
    db.create_all()

    # Create demo company and employee if none exist
    comp = Company.query.first()
    if not comp:
        comp = Company(name='Demo Company', address='123 Demo St', business_number='BN123')
        db.session.add(comp)
        db.session.commit()

    emp = Employee.query.first()
    if not emp:
        emp = Employee(first_name='Jane', last_name='Doe', address='456 Employee Rd', sin='123456789', pay_rate=30.0, payroll_frequency='biweekly', company_id=comp.id)
        db.session.add(emp)
        db.session.commit()

    # Create a payroll line for demo
    pl = PayrollLine.query.order_by(PayrollLine.id.desc()).first()
    if not pl:
        gross = 2000.0
        calc = calculate_payroll(gross)
        pl = PayrollLine(
            employee_id=emp.id,
            gross=gross,
            net=calc['net_pay'],
            cpp_employee=calc['cpp_employee'],
            ei_employee=calc['ei_employee'],
            ei_employer=calc['ei_employer'],
            federal_tax=calc['federal_tax'],
            ontario_tax=calc['ontario_tax'],
            total_employee_deductions=calc['total_employee_deductions'],
            employer_total_cost=calc['employer_total_cost'],
            total_remittance=calc['total_remittance'],
            period_start=datetime.date.today() - datetime.timedelta(days=14),
            period_end=datetime.date.today(),
            pay_date=datetime.date.today(),
        )
        db.session.add(pl)
        db.session.commit()

# Call the route in a test request context to generate PDF bytes
with app.test_request_context('/reports/paystubs_pdf', method='POST', data={}):
    resp = reports_paystubs_pdf()

# The route returns (bytes, status, headers)
if isinstance(resp, tuple):
    data = resp[0]
else:
    # fallback if a Flask Response is returned
    data = resp.get_data()

with open(OUT_PATH, 'wb') as f:
    f.write(data)

print('Paystubs written to:', OUT_PATH)
