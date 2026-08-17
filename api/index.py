"""
Vercel Serverless Function entrypoint for QView.
Delegates all API routes and requests to the unified QViewHandler.
"""

import sys
import os

# Add project root directory to Python search path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from server import QViewHandler

# Export handler for Vercel Python runtime
handler = QViewHandler
app = QViewHandler
application = QViewHandler
