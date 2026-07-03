"""Presentation styling constants for Sentinel PDF reports."""

from constants import Severity

# Font Sizes
TITLE_FONT_SIZE = 24
HEADER_FONT_SIZE = 16
SUBHEADER_FONT_SIZE = 14
BODY_FONT_SIZE = 10

# Colors
SECTION_HEADER_COLOR = "#2C3E50"  # Dark navy/charcoal
BRAND_ACCENT_COLOR = "#3498DB"    # Sentinel AI blue

SEVERITY_COLORS: dict[str, str] = {
    Severity.CRITICAL: "#E74C3C",  # Red
    Severity.HIGH: "#E67E22",      # Orange
    Severity.MEDIUM: "#F1C40F",    # Yellow
    Severity.LOW: "#3498DB",       # Blue
    Severity.NONE: "#95A5A6",      # Neutral gray
}
