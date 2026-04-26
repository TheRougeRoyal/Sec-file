# Secure File Transfer System

A Django-based secure file storage system using ECC encryption (SECP256R1 + AES-256-GCM).

## Requirements

- Python 3.12 or higher

## Setup

### 1. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run migrations

```bash
python manage.py migrate
```

### 4. Create a superuser (optional, for admin access)

```bash
python manage.py createsuperuser
```

### 5. Collect static files

```bash
python manage.py collectstatic --noinput
```

## Running the Dev Server

```bash
python manage.py runserver
```

The app runs at http://127.0.0.1:8000/.

## Running Tests

```bash
python manage.py test
```

To run tests for a specific app:

```bash
python manage.py test crypto.tests
python manage.py test files.tests
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | insecure dev key | Django secret key. Replace in production. |
| `DEBUG` | `True` | Set to `False` for production. |
| `ALLOWED_HOSTS` | `127.0.0.1,localhost` | Comma-separated list of valid hostnames. |

Example:

```bash
export SECRET_KEY='your-secure-secret-key'
export DEBUG='False'
python manage.py runserver
```
