"""Minimal sanitization utilities for removing taint from CBlock content."""

from mellea.stdlib.base import CBlock


def sanitize(cblock: CBlock) -> CBlock:
    """Sanitize a CBlock by marking it as sanitized.
    
    This is a minimal sanitization that simply marks the content as safe
    without modifying the actual content. The developer is responsible
    for ensuring the content is actually safe.
    
    Args:
        cblock: The CBlock to sanitize
        
    Returns:
        A new CBlock with the same content but marked as sanitized
    """
    return _create_sanitized_cblock(cblock, cblock.value)


def _create_sanitized_cblock(original: CBlock, content: str) -> CBlock:
    """Create a sanitized CBlock with updated metadata."""
    from mellea.security import SecurityLevel, SecurityMetadata
    
    sanitized = CBlock(content, original._meta.copy())
    sanitized._meta["_security"] = SecurityMetadata(level=SecurityLevel.SANITIZED)
    
    return sanitized
