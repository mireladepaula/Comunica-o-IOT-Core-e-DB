from __future__ import absolute_import, division, print_function


class CryptoError(Exception):
    """
    Base exception for all nacl related errors
    """


class BadSignatureError(CryptoError):
    """
    Raised when the signature was forged or otherwise corrupt.
    """


class RuntimeError(RuntimeError, CryptoError):
    pass


class AssertionError(AssertionError, CryptoError):
    pass


class TypeError(TypeError, CryptoError):
    pass


class ValueError(ValueError, CryptoError):
    pass


class InvalidkeyError(CryptoError):
    pass


class CryptPrefixError(InvalidkeyError):
    pass


class UnavailableError(RuntimeError):
    """
    is a subclass of :class:`~nacl.exceptions.RuntimeError`, raised when
    trying to call functions not available in a minimal build of
    libsodium.
    """
    pass


def ensure(cond, *args, **kwds):
    """
    Return if a condition is true, otherwise raise a caller-configurable
    :py:class:`Exception`
    :param bool cond: the condition to be checked
    :param sequence args: the arguments to be passed to the exception's
                          constructor
    The only accepted named parameter is `raising` used to configure the
    exception to be raised if `cond` is not `True`
    """
    _CHK_UNEXP = 'check_condition() got an unexpected keyword argument {0}'

    raising = kwds.pop('raising', AssertionError)
    if kwds:
        raise TypeError(_CHK_UNEXP.format(repr(kwds.popitem()[0])))

    if cond is True:
        return
    raise raising(*args)
