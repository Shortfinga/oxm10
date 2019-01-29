#!/usr/bin/env python3
#encoding: utf-8

from setuptools import setup


VERSION = 0.1

REQUIRED = [
    "cryptography"
]

setup(
    name="oxm10",
    version=VERSION,
    description="module to encrypt data with aes and rsa",
    long_description_content_type='text/markdown',
    author="Shortfinga",
    author_email="shortfinga@posteo.org",
    python_requires=">=3.5.0",
    url="https://github.com/Shortfinga/oxm10",
    packages=["oxm10"],
    package_dir={"oxm10": "oxm10"},
    install_requires=REQUIRED,
    include_package_data=True,
    license='MIT',
    classifiers=[
        # Trove classifiers
        # Full list: https://pypi.python.org/pypi?%3Aaction=list_classifiers
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5"
    ]
)

