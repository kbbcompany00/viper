"""
ViperSec 2025 - Next-Generation AI-Driven Cybersecurity Testing Platform
"""

__version__ = "2025.1.0"
__author__ = "ViperSec Security Team"
__description__ = "Revolutionary cybersecurity testing platform with AI-powered vulnerability detection"

from .core.engine import ViperSecEngine
from .core.scanner import SecurityScanner
from .core.config import Config

__all__ = ['ViperSecEngine', 'SecurityScanner', 'Config']