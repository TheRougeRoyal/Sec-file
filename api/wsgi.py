"""
Vercel Serverless WSGI Adapter for Django

This module wraps the Django WSGI application with WhiteNoise for
efficient static file serving in serverless environments.
"""
import os
import sys

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
os.environ.setdefault('VERCEL', '1')  # Enable Vercel-specific settings

# Import Django WSGI application
from django.core.wsgi import get_wsgi_application
from whitenoise import WhiteNoise

application = get_wsgi_application()

# Wrap with WhiteNoise for static file serving
application = WhiteNoise(application, root='staticfiles/')
