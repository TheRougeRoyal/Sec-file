# Deployment Guide

## Overview

This app requires two external managed services:

- **PostgreSQL** — managed database (e.g. Supabase, Railway, Render, Neon)
- **S3-compatible object storage** — for user-uploaded media files (e.g. AWS S3, Cloudflare R2, Backblaze B2)

Both are required. The app will refuse to start in production (`DEBUG=False`) without them.

---

## Local Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

No external services needed locally. SQLite and local disk storage are used.

## Production (Any Cloud Platform)

### Required Environment Variables

| Variable | Example | Description |
|---|---|---|
| `DATABASE_URL` | `postgres://user:pass@host:5432/dbname` | PostgreSQL connection string |
| `AWS_S3_BUCKET_NAME` | `my-app-media` | S3 bucket for file uploads |
| `AWS_ACCESS_KEY_ID` | `AKIA...` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | `...` | AWS secret key |
| `AWS_S3_REGION_NAME` | `us-east-1` | S3 region (optional, defaults to us-east-1) |
| `AWS_S3_ENDPOINT_URL` | `https://...` | S3-compatible endpoint for R2/B2/etc. (optional for AWS S3) |
| `AWS_S3_CUSTOM_DOMAIN` | `cdn.example.com` | Public media host without protocol (optional) |
| `SECRET_KEY` | `...` | Django secret key — use a strong random value |
| `DEBUG` | `false` | Must be `false` in production |
| `ALLOWED_HOSTS` | `example.com,www.example.com` | Comma-separated production hostnames |
| `PRIVATE_KEY_PASSPHRASE` | `...` | Passphrase to encrypt user ECC private keys at rest. Required in production. |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | `false` | Set to `true` only when every subdomain is HTTPS-only. |
| `SECURE_HSTS_PRELOAD` | `false` | Set to `true` only when the domain is ready for browser HSTS preload. |

### Private Key Encryption

User ECC private keys are encrypted at rest using a passphrase-derived AES-256 key (via PBKDF2 + Fernet).

`PRIVATE_KEY_PASSPHRASE` must be set in production. Without it, the app still functions but stores private keys as plain text in the database — which is acceptable only for local development.

**Important:** If `PRIVATE_KEY_PASSPHRASE` is lost, all stored private keys are unrecoverable and users must re-upload their files.

Setting `PRIVATE_KEY_PASSPHRASE` in production will automatically re-encrypt newly accessed keys on next save. Existing encrypted keys in the database are preserved; they are re-saved in encrypted form when the model is next touched.

### Database

The app uses `dj-database-url` to parse `DATABASE_URL`. Any PostgreSQL provider works:

- [Supabase](https://supabase.com) — free tier available
- [Railway](https://railway.app) — free tier available
- [Render](https://render.com) — free tier available
- [Neon](https://neon.tech) — free tier available
- AWS RDS, Google Cloud SQL, Azure Database — any standard Postgres host

### File Storage

Uploaded files go to S3-compatible storage via `django-storages`. Supports:

- AWS S3
- Cloudflare R2 (S3-compatible, no egress fees)
- Backblaze B2 (S3-compatible, cheap egress)
- Any S3-compatible API

For Cloudflare R2 or another S3-compatible provider, set `AWS_S3_ENDPOINT_URL` to the provider endpoint and optionally set `AWS_S3_CUSTOM_DOMAIN` to the public media domain.

### Running Migrations

In production, run migrations manually after deployment:

```bash
python manage.py migrate
```

Do not rely on the build script for migrations — on ephemeral serverless platforms, build and runtime environments may differ.

---

## Vercel Deployment

Vercel deploys this Django app via a custom WSGI wrapper (`api/wsgi.py`).

### Required Vercel Environment Variables

Set these in the Vercel project dashboard under **Settings → Environment Variables**:

- `DATABASE_URL` — your managed Postgres connection string
- `AWS_S3_BUCKET_NAME` — your S3/R2 bucket name
- `AWS_ACCESS_KEY_ID` — AWS/R2 access key
- `AWS_SECRET_ACCESS_KEY` — AWS/R2 secret key
- `SECRET_KEY` — a strong random secret
- `DEBUG` — `false`
- `ALLOWED_HOSTS` — your production domain(s)
- `PRIVATE_KEY_PASSPHRASE` — passphrase for encrypting user ECC private keys at rest
- `AWS_S3_REGION_NAME`, `AWS_S3_ENDPOINT_URL`, and `AWS_S3_CUSTOM_DOMAIN` as needed for your storage provider

The build will fail if `DATABASE_URL` or `AWS_S3_BUCKET_NAME` is missing when `DEBUG=false`.

### Build Configuration

These are committed in `vercel.json`:

- Build command: `bash vercel_build.sh`
- Install command: `pip install -r requirements.txt`
- Output directory: leave blank (Django serves via WSGI)

---

## Security Notes

- `DEBUG=False` is enforced for production behavior. Do not set `DEBUG=true` in production.
- `SECRET_KEY` must be a strong random value, not the insecure default.
- `ALLOWED_HOSTS` must list only your actual production hostnames.
- CSRF protection is enabled; form views work normally.
- `X_FRAME_OPTIONS=DENY` is set to prevent clickjacking.
