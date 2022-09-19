from __future__ import absolute_import
from __future__ import division

import os
import re
import warnings

import six




__all__ = [
    "__title__", "__summary__", "__uri__", "__version__", "__author__",
    "__email__", "__license__", "__copyright__",
    "gensalt", "hashpw", "kdf", "checkpw",
]


_normalize_re = re.compile(br"^\$2y\$")


def gensalt(rounds=12, prefix=b"2b"):
    if prefix not in (b"2a", b"2b"):
        raise ValueError("Supported prefixes are b'2a' or b'2b'")

    if rounds < 4 or rounds > 31:
        raise ValueError("Invalid rounds")

    salt = os.urandom(16)
    output = _bcrypt.ffi.new("char[]", 30)
    _bcrypt.lib.encode_base64(output, salt, len(salt))

    return (
        b"$" + prefix + b"$" + ("%2.2u" % rounds).encode("ascii") + b"$" +
        _bcrypt.ffi.string(output)
    )


def hashpw(password, salt):
    if isinstance(password, six.text_type) or isinstance(salt, six.text_type):
        raise TypeError("Unicode-objects must be encoded before hashing")

    if b"\x00" in password:
        raise ValueError("password may not contain NUL bytes")


    password = password[:72]


    original_salt, salt = salt, _normalize_re.sub(b"$2b$", salt)

    hashed = _bcrypt.ffi.new("char[]", 128)
    retval = _bcrypt.lib.bcrypt_hashpass(password, salt, hashed, len(hashed))

    if retval != 0:
        raise ValueError("Invalid salt")


    return original_salt[:4] + _bcrypt.ffi.string(hashed)[4:]


def checkpw(password, hashed_password):
    if (isinstance(password, six.text_type) or
            isinstance(hashed_password, six.text_type)):
        raise TypeError("Unicode-objects must be encoded before checking")

    if b"\x00" in password or b"\x00" in hashed_password:
        raise ValueError(
            "password and hashed_password may not contain NUL bytes"
        )

    ret = hashpw(password, hashed_password)

    if len(ret) != len(hashed_password):
        return False

    return _bcrypt.lib.timingsafe_bcmp(ret, hashed_password, len(ret)) == 0


def kdf(password, salt, desired_key_bytes, rounds, ignore_few_rounds=False):
    if isinstance(password, six.text_type) or isinstance(salt, six.text_type):
        raise TypeError("Unicode-objects must be encoded before hashing")

    if len(password) == 0 or len(salt) == 0:
        raise ValueError("password and salt must not be empty")

    if desired_key_bytes <= 0 or desired_key_bytes > 512:
        raise ValueError("desired_key_bytes must be 1-512")

    if rounds < 1:
        raise ValueError("rounds must be 1 or more")

    if rounds < 50 and not ignore_few_rounds:

        warnings.warn((
            "Warning: bcrypt.kdf() called with only {0} round(s). "
            "This few is not secure: the parameter is linear, like PBKDF2.")
            .format(rounds),
            UserWarning,
            stacklevel=2,
        )

    key = _bcrypt.ffi.new("uint8_t[]", desired_key_bytes)
    res = _bcrypt.lib.bcrypt_pbkdf(
        password, len(password), salt, len(salt), key, len(key), rounds
    )
    _bcrypt_assert(res == 0)

    return _bcrypt.ffi.buffer(key, desired_key_bytes)[:]


def _bcrypt_assert(ok):
    if not ok:
        raise SystemError("bcrypt assertion failed")