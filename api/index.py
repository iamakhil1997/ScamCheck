import sys
import os

# Add root directory to python path for Vercel environment
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app
