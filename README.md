# SleepyXgift — Flask edition

100% same UI + Garena API as the original. Pure Python + one HTML file.
No build step. Runs on any free Python host.

## Run locally

```bash
pip install -r requirements.txt
python app.py
# open http://localhost:5000
```

## Deploy on free hosts

### Render.com (recommended)
1. Push these files to a GitHub repo
2. New → Web Service → connect repo
3. Runtime: **Python 3**
4. Build command: `pip install -r requirements.txt`
5. Start command: `gunicorn app:app`
6. Click Deploy. Done.

### Replit
1. Create new Python Repl, upload all files
2. Run button works out of the box (it runs `python app.py`)

### Railway / Fly.io / Koyeb
Procfile is included — auto-detected.

### PythonAnywhere
1. Upload files, create a Flask web app
2. Point WSGI file to `app.py` (`from app import app as application`)

## Files
- `app.py` — Flask backend, Garena protobuf + AES logic
- `templates/index.html` — full UI (Tailwind via CDN, vanilla JS)
- `static/logo.jpg` — logo
- `requirements.txt`, `Procfile`, `runtime.txt` — deploy config
