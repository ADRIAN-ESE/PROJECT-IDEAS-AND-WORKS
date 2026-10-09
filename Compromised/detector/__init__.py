"""Phishing and compromised-email detection package."""

from .engine import AnalysisResult, Finding, analyze_email
from .pipeline import analyse_full, parse_eml

__all__ = ["analyze_email", "AnalysisResult", "Finding", "analyse_full", "parse_eml"]
