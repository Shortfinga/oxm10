#!/usr/bin/env python3
#encoding: utf-8

"""test if oxm10 works bidirectionally"""

import os
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from oxm10 import (
    aes_encrypt,
    aes_decrypt,
    rsa_encrypt,
    rsa_decrypt,
    encrypt,
    decrypt
)


class Bidirectional(unittest.TestCase):
    def test_aes(self):
        plaintext = os.urandom(100)
        ciphertext, key = aes_encrypt(plaintext)
        encrypted = aes_decrypt(key, ciphertext)
        self.assertTrue(
            encrypted == plaintext
        )

    def test_rsa(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        plaintext = os.urandom(100)
        ciphertext = rsa_encrypt(
            public_key,
            plaintext
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        encrypted = rsa_decrypt(
            pem,
            ciphertext
        )
        self.assertTrue(
            encrypted == plaintext
        )

    def test_combined(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        plaintext = os.urandom(100)
        encrypted_key, ciphertext = encrypt(public_key, plaintext)
        encrypted = decrypt(
            private_key,
            encrypted_key,
            ciphertext
        )
        self.assertTrue(
            encrypted == plaintext
        )
