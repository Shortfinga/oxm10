#!/usr/bin/env python3
#encoding: utf-8

"""test if oxm10 is compatible with openssl"""

import os
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from oxm10 import (
    aes_encrypt,
    rsa_encrypt
)


class CompatibilityOpenSSL(unittest.TestCase):
    """test compatibility with openssl"""
    def test_aes_encryption(self):
        plaintext = os.urandom(100)
        ciphertext, iv_key = aes_encrypt(plaintext)
        iv = iv_key[:16]
        key = iv_key[16:]
        cmd_result = subprocess.run(
            [
                "openssl",
                "enc",
                "-d",
                "-aes256",
                "-iv",
                iv.hex(),
                "-K",
                key.hex()
            ],
            input=ciphertext,
            capture_output=True
        )
        self.assertTrue(
            cmd_result.stdout == plaintext
        )

    def test_rsa_encryption(self):
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
        tmpfile = tempfile.NamedTemporaryFile()
        tmpfile.write(pem)
        tmpfile.flush()
        os.fsync(tmpfile)
        cmd_result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-decrypt",
                "-inkey",
                tmpfile.name,
                "-pkeyopt",
                "rsa_padding_mode:oaep",
                "-pkeyopt",
                "rsa_oaep_md:sha256",
                "-pkeyopt",
                "rsa_mgf1_md:sha256"
            ],
            input=ciphertext,
            capture_output=True
        )
        tmpfile.close()
        self.assertTrue(
            cmd_result.stdout == plaintext
        )
