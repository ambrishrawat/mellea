"""Security properties for mellea - taint tracking and control flow management."""

from enum import Enum
from dataclasses import dataclass


class SecurityLevel(Enum):
    """Security levels for CBlock content."""
    SAFE = "safe"           # Trusted, sanitized content
    TAINTED = "tainted"     # External/untrusted content
    PROPRIETARY = "proprietary"  # Sensitive internal content
    SANITIZED = "sanitized" # Content that has been sanitized


@dataclass
class SecurityMetadata:
    """Minimal metadata tracking security properties of CBlock content."""
    level: SecurityLevel
    
    def is_safe(self) -> bool:
        """Check if this metadata represents safe content."""
        return self.level in [SecurityLevel.SAFE, SecurityLevel.SANITIZED]
    
    def is_tainted(self) -> bool:
        """Check if this metadata represents tainted content."""
        return self.level in [SecurityLevel.TAINTED, SecurityLevel.PROPRIETARY]


class SecurityError(Exception):
    """Raised when security constraints are violated."""
    pass


# Import decorators and utilities
from .decorators import privileged
from .sanitization import sanitize

# Export main classes and decorators
__all__ = ["SecurityLevel", "SecurityMetadata", "SecurityError", "privileged", "sanitize"]
