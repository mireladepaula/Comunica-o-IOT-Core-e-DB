from __future__ import absolute_import, division, print_function


_default_backend = None


def default_backend():
    global _default_backend

    if _default_backend is None:
        from cryptography.hazmat.backends.openssl.backend import backend
        _default_backend = backend

    return _default_backend