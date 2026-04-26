#!/bin/bash
# Vercel Build Script for Django
#
# Production deployment requires:
#   DATABASE_URL    - PostgreSQL connection string (e.g. postgres://user:pass@host:5432/dbname)
#   AWS_S3_BUCKET_NAME       - S3 bucket for media file storage
#   AWS_ACCESS_KEY_ID        - AWS access key
#   AWS_SECRET_ACCESS_KEY    - AWS secret key
#   PRIVATE_KEY_PASSPHRASE   - encryption passphrase for stored private keys
#
# Required environment variables must be set in the Vercel project dashboard.
# Without them, the app will refuse to start (ImproperlyConfigured).

set -e

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    PYTHON_BIN="python"
fi

echo "Collecting static files..."
"$PYTHON_BIN" manage.py collectstatic --noinput

echo "Build complete!"
