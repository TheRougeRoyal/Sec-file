# Secure File Transfer System using ECC

## Overview

This is a full-stack Django web application for secure file transfer.
Users can register, log in, upload text/image files, and securely view/download files.
All uploaded files are encrypted with ECC-based key exchange and per-file encryption before storage.

## Features

- User authentication (register, login, logout)
- Password hashing and validation via Django auth
- Profile editing
- ECC key pair generation per user
- Encrypted file storage for text and image files
- Decryption only for authorized owner
- CSRF protection and authenticated access control
- Dashboard and file management pages

## Tech Stack

- Python + Django
- SQLite (default for development)
- tinyec for ECC primitives
- HTML, CSS, JavaScript-ready templates

## Project Structure

- accounts: authentication and profile
- files: upload, encrypted storage, view/download
- crypto: ECC keypair and encryption/decryption logic
- config: Django settings and root URLs

## Setup and Run

1. Create and activate virtual environment (already available in this workspace).
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run migrations:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```
4. Create admin user (optional):
   ```bash
   python manage.py createsuperuser
   ```
5. Create sample test user:
   ```bash
   python manage.py create_test_user
   ```
6. Start server:
   ```bash
   python manage.py runserver
   ```

## Example Test User Flow

1. Open http://127.0.0.1:8000/accounts/login/
2. Login with sample user: testuser / Test@12345
3. Open dashboard
4. Upload a text or image file from Upload page
5. Open My Files and use View or Download to decrypt on access

## Security Notes

- User sessions and auth are handled by Django middleware.
- File access is restricted to file owners.
- Files are encrypted before persistence; plaintext is returned only for authorized requests.

## Run Tests

```bash
python manage.py test
```

## Deploy to Vercel

### Prerequisites

1. Install Vercel CLI:
   ```bash
   npm install -g vercel
   ```

2. Login to Vercel:
   ```bash
   vercel login
   ```

### Deployment Steps

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Collect static files:**
   ```bash
   python manage.py collectstatic --noinput
   ```

3. **Deploy to Vercel:**
   ```bash
   vercel
   ```

### Environment Variables

Set these in your Vercel project settings (vercel.json or Vercel dashboard):

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Django secret key for production | (auto-generated) |
| `DEBUG` | Enable debug mode | `False` |
| `ALLOWED_HOSTS` | Comma-separated allowed hosts | `.vercel.app` |

### Important Notes

- **Database**: This deployment uses SQLite stored in `/tmp/` which is ephemeral. Data will be lost between serverless invocations.
- **For production**: Consider migrating to PostgreSQL with a persistent database service like:
  - Vercel Postgres
  - Neon
  - Supabase
  - AWS RDS

- **Media Files**: Uploaded files are stored in `/tmp/media` and are also ephemeral. For persistent storage, use:
  - AWS S3
  - Vercel Blob Storage
  - Cloudinary

### Local Preview

To test the Vercel deployment locally:

```bash
vercel dev
```

### Troubleshooting

1. **502 Bad Gateway**: Check that `DJANGO_SETTINGS_MODULE` is set correctly
2. **Static files not loading**: Run `python manage.py collectstatic --noinput` before deploying
3. **Database errors**: Ensure migrations are run during build
