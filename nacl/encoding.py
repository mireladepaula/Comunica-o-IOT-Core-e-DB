from __future__ import absolute_import, division, print_function

import base64
import binascii


class RawEncoder(object):

    @staticmethod
    def encode(data):
        return data

    @staticmethod
    def decode(data):
        return data


class HexEncoder(object):

    @staticmethod
    def encode(data):
        return binascii.hexlify(data)

    @staticmethod
    def decode(data):
        return binascii.unhexlify(data)


class Base16Encoder(object):

    @staticmethod
    def encode(data):
        return base64.b16encode(data)

    @staticmethod
    def decode(data):
        return base64.b16decode(data)


class Base32Encoder(object):

    @staticmethod
    def encode(data):
        return base64.b32encode(data)

    @staticmethod
    def decode(data):
        return base64.b32decode(data)


class Base64Encoder(object):

    @staticmethod
    def encode(data):
        return base64.b64encode(data)

    @staticmethod
    def decode(data):
        return base64.b64decode(data)


class URLSafeBase64Encoder(object):

    @staticmethod
    def encode(data):
        return base64.urlsafe_b64encode(data)

    @staticmethod
    def decode(data):
        return base64.urlsafe_b64decode(data)


class Encodable(object):

    def encode(self, encoder=RawEncoder):
        return encoder.encode(bytes(self))