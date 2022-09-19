from __future__ import absolute_import, division, print_function

from nacl import exceptions as exc
from nacl._sodium import ffi, lib
from nacl.exceptions import ensure



crypto_hash_BYTES = lib.crypto_hash_sha512_bytes()
crypto_hash_sha256_BYTES = lib.crypto_hash_sha256_bytes()
crypto_hash_sha512_BYTES = lib.crypto_hash_sha512_bytes()


def crypto_hash(message):
    """
    Hashes and returns the message ``message``.

    :param message: bytes
    :rtype: bytes
    """
    digest = ffi.new("unsigned char[]", crypto_hash_BYTES)
    rc = lib.crypto_hash(digest, message, len(message))
    ensure(rc == 0,
           'Unexpected library error',
           raising=exc.RuntimeError)
    return ffi.buffer(digest, crypto_hash_BYTES)[:]


def crypto_hash_sha256(message):
    """
    Hashes and returns the message ``message``.

    :param message: bytes
    :rtype: bytes
    """
    digest = ffi.new("unsigned char[]", crypto_hash_sha256_BYTES)
    rc = lib.crypto_hash_sha256(digest, message, len(message))
    ensure(rc == 0,
           'Unexpected library error',
           raising=exc.RuntimeError)
    return ffi.buffer(digest, crypto_hash_sha256_BYTES)[:]


def crypto_hash_sha512(message):
    """
    Hashes and returns the message ``message``.

    :param message: bytes
    :rtype: bytes
    """
    digest = ffi.new("unsigned char[]", crypto_hash_sha512_BYTES)
    rc = lib.crypto_hash_sha512(digest, message, len(message))
    ensure(rc == 0,
           'Unexpected library error',
           raising=exc.RuntimeError)
    return ffi.buffer(digest, crypto_hash_sha512_BYTES)[:]