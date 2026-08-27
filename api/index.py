import sys
import os

# Explicitly add project root to sys.path so 'app' package imports work cleanly on Vercel
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    from app.main import app
except Exception as e:
    # Fallback error handler if startup fails
    from fastapi import FastAPI
    app = FastAPI()
    
    @app.get("/{full_path:path}")
    def error_handler(full_path: str):
        return {"error": "Serverless Startup Failure", "detail": str(e)}
