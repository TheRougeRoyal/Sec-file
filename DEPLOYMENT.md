# Vercel Deployment Guide

## Quick Deploy

```bash
# 1. Install Vercel CLI
npm install -g vercel

# 2. Login to Vercel
vercel login

# 3. Deploy
vercel
```

## Files Created for Vercel

| File | Purpose |
|------|---------|
| `api/wsgi.py` | Vercel serverless entry point with WhiteNoise |
| `vercel.json` | Vercel configuration (routes, builds, env) |
| `.vercelignore` | Files to exclude from deployment |
| `.env.example` | Environment variable template |

## Important Limitations

### SQLite on Vercel (Ephemeral Storage)

- SQLite database stored in `/tmp/` is **ephemeral**
- Data persists between requests in the same lambda container
- Data **will be lost** when lambda freezes (after ~5 minutes of inactivity)
- Not suitable for production use

### Media Files

- Uploaded files stored in `/tmp/media` are also ephemeral
- Files will be lost between lambda invocations

## Production Recommendations

### 1. Use PostgreSQL for Persistent Database

```bash
# Add to requirements.txt
psycopg2-binary==2.9.9

# Update settings.py to use DATABASE_URL
import dj_database_url
DATABASES = {
    'default': dj_database_url.config(
        conn_max_age=600,
        default='sqlite:///tmp/db.sqlite3'
    )
}
```

Options:
- **Vercel Postgres**: `vercel postgres create`
- **Neon**: Free tier, serverless PostgreSQL
- **Supabase**: Free PostgreSQL hosting

### 2. Use Cloud Storage for Media Files

For persistent file storage:
- **AWS S3**: Use `django-storages` with S3 backend
- **Vercel Blob**: `vercel blob create`
- **Cloudinary**: For image/video files

Example with S3:
```python
# settings.py
INSTALLED_APPS += ['storages']

AWS_STORAGE_BUCKET_NAME = 'your-bucket'
AWS_S3_REGION_NAME = 'us-east-1'
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')

DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
```

## Environment Variables

Set these in Vercel Dashboard > Project Settings > Environment Variables:

| Variable | Description | Required |
|----------|-------------|----------|
| `SECRET_KEY` | Django secret key | Yes |
| `DEBUG` | Set to `False` | Yes |
| `ALLOWED_HOSTS` | Your domain(s) | Optional |

## Local Testing

```bash
# Test with Vercel environment
export VERCEL=1
python manage.py runserver
```

## Troubleshooting

### 502 Bad Gateway
- Check `DJANGO_SETTINGS_MODULE` is set
- Verify `PYTHONPATH` includes project root

### Static Files Not Loading
- Ensure `collectstatic` runs in build
- Check WhiteNoise is in MIDDLEWARE

### Database Errors
- Migrations run automatically during build
- For local testing: `python manage.py migrate`

## Commands Reference

```bash
# Link project to Vercel
vercel link

# Deploy to preview
vercel

# Deploy to production
vercel --prod

# View logs
vercel logs <deployment-url>
```
