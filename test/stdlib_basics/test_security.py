"""Test security properties for CBlock."""

import pytest
from mellea.stdlib.base import CBlock
from mellea.security import privileged, sanitize, SecurityError



def test_sanitize_function():
    """Test the minimal sanitize function."""
    
    # Test marking content as tainted
    email = CBlock("Hello <script>alert('xss')</script> world")
    email.mark_tainted("tainted")
    
    assert not email.is_safe()
    assert email.value == "Hello <script>alert('xss')</script> world"
    
    # Test sanitize function (minimal - just marks as sanitized)
    safe_email = sanitize(email)
    
    assert safe_email.is_safe()
    assert safe_email._meta["_security"].level.value == "sanitized"
    assert not email.is_safe() # check if the original content is still tainted


def test_privileged_decorator():
    """Test the @privileged decorator functionality."""
    
    @privileged
    def process_content(content: CBlock) -> str:
        return f"Processed: {content}"
    
    # Test with safe content
    safe_content = CBlock("Safe content")
    safe_content.mark_tainted("safe")
    
    result = process_content(safe_content)
    assert result == "Processed: Safe content"
    
    # Test with tainted content
    tainted_content = CBlock("Tainted content")
    tainted_content.mark_tainted("tainted")
    
    with pytest.raises(SecurityError):
        process_content(tainted_content)


def test_security_levels():
    """Test different security levels."""
    
    # Test SAFE level
    safe_block = CBlock("Safe content")
    safe_block.mark_tainted("safe")
    assert safe_block.is_safe()
    
    # Test TAINTED level
    tainted_block = CBlock("Tainted content")
    tainted_block.mark_tainted("tainted")
    assert not tainted_block.is_safe()
    
    # Test PROPRIETARY level
    proprietary_block = CBlock("Proprietary content")
    proprietary_block.mark_tainted("proprietary")
    assert not proprietary_block.is_safe()
    
    # Test SANITIZED level
    sanitized_block = CBlock("Sanitized content")
    sanitized_block.mark_tainted("sanitized")
    assert sanitized_block.is_safe()


def test_security_metadata_minimal():
    """Test that security metadata is minimal."""
    
    email = CBlock("Test content")
    email.mark_tainted("tainted")
    
    security_meta = email._meta["_security"]
    
    # Should only have level and methods
    assert hasattr(security_meta, 'level')
    assert hasattr(security_meta, 'is_safe')
    assert hasattr(security_meta, 'is_tainted')

