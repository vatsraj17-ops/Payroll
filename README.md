# Payroll App (Ontario - demo)

Simple Flask demo to enter companies, employees, and calculate payroll deductions (CPP, EI, federal & Ontario tax). This is a minimal scaffold for development and testing only.

Setup (Windows):

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 in your browser.

Notes:
- Calculation rules in `calc.py` are simplified examples; validate against official CRA rules for production.
- No banking/direct deposit functionality included.

## DigitalOcean (Canada / Toronto) deployment

This app can be deployed to **DigitalOcean App Platform** with **DigitalOcean Managed PostgreSQL** in the **Toronto** region to satisfy Canada data residency.

**Run command (App Platform)**

- `gunicorn app:app`

**Required environment variables (App Platform → Settings → Environment Variables)**

- `SECRET_KEY`: long random string
- `DATABASE_URL`: provided by DigitalOcean Managed PostgreSQL (ensure the DB cluster is Toronto)

**Recommended environment variables**

- `FLASK_ENV=production`
- `APP_USERNAME`: bootstrap admin username (defaults to `admin`)
- `APP_PASSWORD_HASH`: bootstrap admin password hash (preferred) OR `APP_PASSWORD` for initial setup

Notes:
- The app uses SQLite automatically if `DATABASE_URL` is not set (local dev).
- The SQLite “lightweight migration” code only runs when using SQLite; for production Postgres you should use proper migrations.
