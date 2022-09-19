from __future__ import absolute_import, division, print_function

import nacl.exceptions as exc
from nacl._sodium import ffi, lib
from nacl.exceptions import ensure


has_crypto_shorthash_siphashx24 = \
    bool(lib.PYNACL_HAS_CRYPTO_SHORTHASH_SIPHASHX24)

BYTES = lib.crypto_shorthash_siphash24_bytes()
KEYBYTES = lib.crypto_shorthash_siphash24_keybytes()

XBYTES = 0
XKEYBYTES = 0

if has_crypto_shorthash_siphashx24:
    XBYTES = lib.crypto_shorthash_siphashx24_bytes()
    XKEYBYTES = lib.crypto_shorthash_siphashx24_keybytes()


def crypto_shorthash_siphash24(data, key):
    """Compute a fast, cryptographic quality, keyed hash of the input data

    :param data:
    :type data: bytes
    :param key: len(key) must be equal to
                :py:data:`.KEYBYTES` (16)
    :type key: bytes
    """
    if len(key) != KEYBYTES:
        raise exc.ValueError(
            "Key length must be exactly {0} bytes".format(KEYBYTES))
    digest = ffi.new("unsigned char[]", BYTES)
    rc = lib.crypto_shorthash_siphash24(digest, data, len(data), key)

    ensure(rc == 0, raising=exc.RuntimeError)
    return ffi.buffer(digest, BYTES)[:]


def crypto_shorthash_siphashx24(data, key):
    """Compute a fast, cryptographic quality, keyed hash of the input data

    :param data:
    :type data: bytes
    :param key: len(key) must be equal to
                :py:data:`.XKEYBYTES` (16)
    :type key: bytes
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(has_crypto_shorthash_siphashx24,
           'Not available in minimal build',
           raising=exc.UnavailableError)

    if len(key) != XKEYBYTES:
        raise exc.ValueError(
            "Key length must be exactly {0} bytes".format(XKEYBYTES))
    digest = ffi.new("unsigned char[]", XBYTES)
    rc = lib.crypto_shorthash_siphashx24(digest, data, len(data), key)

    ensure(rc == 0, raising=exc.RuntimeError)
    return ffi.buffer(digest, XBYTES)[:]