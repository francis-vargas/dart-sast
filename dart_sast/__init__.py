"""dart_sast — SAST for Dart/Flutter."""
from .analyzer import analyze_directory, analyze_file, ALL_RULES, AnalysisResult, Finding, Severity

__version__ = "1.0.0"
__all__ = [
    "analyze_directory", "analyze_file", "ALL_RULES",
    "AnalysisResult", "Finding", "Severity",
]