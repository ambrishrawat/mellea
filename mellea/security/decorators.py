"""Security decorators for controlling access to tainted content."""

from functools import wraps
from typing import Callable, Any
from mellea.stdlib.base import CBlock
from mellea.security import SecurityError


def privileged(func: Callable) -> Callable:
    """Decorator for functions that only accept safe/untainted inputs.
    
    Functions decorated with @privileged will raise SecurityError if any
    CBlock argument is tainted. Regular functions (without decorators) 
    accept any security level by default.
    
    Args:
        func: Function to protect with security constraints
        
    Returns:
        Wrapped function that enforces security constraints
        
    Raises:
        SecurityError: If any CBlock argument is tainted
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Check all CBlock arguments for safety
        for arg in args:
            if isinstance(arg, CBlock) and not arg.is_safe():
                raise SecurityError(
                    f"Function {func.__name__} requires safe input, got tainted CBlock "
                )
        
        for key, value in kwargs.items():
            if isinstance(value, CBlock) and not value.is_safe():
                raise SecurityError(
                    f"Function {func.__name__} requires safe input, got tainted CBlock "
                )
        
        return func(*args, **kwargs)
    return wrapper
