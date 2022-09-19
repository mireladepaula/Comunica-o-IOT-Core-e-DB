from __future__ import absolute_import, division, print_function

import hmac
import warnings

from cryptography import utils



if hasattr(hmac, "compare_digest"):
    def bytes_eq(a, b):
        if not isinstance(a, bytes) or not isinstance(b, bytes):
            raise TypeError("a and b must be bytes.")

        return hmac.compare_digest(a, b)

else:
    warnings.warn(
        "Support for your Python version is deprecated. The next version of "
        "cryptography will remove support. Please upgrade to a release "
        "(2.7.7+) that supports hmac.compare_digest as soon as possible.",
        utils.PersistentlyDeprecated2018,
    )

    def bytes_eq(a, b):
        if not isinstance(a, bytes) or not isinstance(b, bytes):
            raise TypeError("a and b must be bytes.")

        return lib.Cryptography_constant_time_bytes_eq(
            a, len(a), b, len(b)
        ) == 1