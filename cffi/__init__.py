__all__ = ['FFI', 'VerificationError', 'VerificationMissing', 'CDefError',
           'FFIError']

from .api import FFI
from .error import CDefError, FFIError, VerificationError, VerificationMissing
from .error import PkgConfigError

__version__ = "1.14.0"
__version_info__ = (1, 14, 0)

__version_verifier_modules__ = "0.8.6"