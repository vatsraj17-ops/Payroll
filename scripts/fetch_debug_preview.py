import os
import sys

# Ensure project root is on sys.path so we can import app
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app import app

OUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'output')
os.makedirs(OUT_DIR, exist_ok=True)
OUT_PATH = os.path.join(OUT_DIR, 'paystubs_debug_preview.pdf')

with app.test_client() as c:
    r = c.get('/debug/paystubs_preview_demo')
    if r.status_code == 200 and r.headers.get('Content-Type','').startswith('application/pdf'):
        with open(OUT_PATH, 'wb') as f:
            f.write(r.data)
        print('Saved debug preview to', OUT_PATH)
    else:
        print('Preview request failed:', r.status_code, r.headers)
