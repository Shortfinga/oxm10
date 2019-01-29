#!/usr/bin/env python3
#encoding: utf-8

"""Module to encrypt stuff

should be compatible with openssl...

Decrypt rsa:

``openssl pkeyutl -decrypt -inkey <private key> -in <encrypted_key> -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256``

Decrypt aes:

``openssl enc -d -aes256 -in ciphertext.enc -iv <iv in hex> -K <key in hex>``
"""

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_encrypt(data: bytes):
    """encrypts data with a "on the fly" generated key

    :param data: bytes, the data you want to encrypt

    :return ciphertext, key: ciphertext are bytes and
        key is iv and key concatenated
        key is always 32 bytes and iv is 16 bytes
    """
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    key = os.urandom(32)
    initialisation_vector = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(initialisation_vector),
        backend=default_backend()
    )
    encrytor = cipher.encryptor()
    ciphertext = encrytor.update(padded_data)
    ciphertext += encrytor.finalize()
    return ciphertext, initialisation_vector+key


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    """decrypts aes encrypted data (from aes_encrypt)

    :param key: iv and key concatenated 48bytes

    :return: plaintext
    """
    cipher = Cipher(
        algorithms.AES(key[16:]),
        modes.CBC(key[:16]),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


def rsa_encrypt(pub_key, data: bytes) -> bytes:
    """encrypts data with the pubkey
    meant to encrypt a key from aes_encrypt

    :param pub_key: bytes or a cryptography Public RSA key,
        if bytes then these will be converted to a pubkey.
    :param data: the data which will be encrypted

    :return: cipher text
    """
    if isinstance(pub_key, bytes):
        pub_key = serialization.load_pem_public_key(
            pub_key,
            default_backend()
        )
    ciphertext = pub_key.encrypt(
        data,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(priv_key, data: bytes) -> bytes:
    """decrypts rsa encrypted data (from rsa_encrypt)
    :param priv_key: bytes or a cryptography RSA private key

    :return: plaintext
    """
    if isinstance(priv_key, bytes):
        priv_key = serialization.load_pem_private_key(
            priv_key,
            password=None,
            backend=default_backend()
        )
    plaintext = priv_key.decrypt(
        data,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def encrypt(pub_key, data: bytes):
    """encrypt data with aes and encrypt the key with rsa
    :param pub_key: bytes or cryptography RSA public key

    :return: encrypted_key, ciphertext
    """
    ciphertext, key = aes_encrypt(data)
    encrypted_key = rsa_encrypt(pub_key, key)
    return encrypted_key, ciphertext


def decrypt(priv_key, encrypted_key: bytes, data: bytes) -> bytes:
    """decrypt data encrypted with encrypt
    :param priv_key: bytes or cryptography RSA private key
    :param encrypted_key: the rsa encrypted aes key
    :param data: the aes encrypted data

    :return: plaintext
    """
    key = rsa_decrypt(priv_key, encrypted_key)
    return aes_decrypt(key, data)
