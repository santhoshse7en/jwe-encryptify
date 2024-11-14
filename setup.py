"""A setuptools-based setup module for the jwe-encryptify package.
For more details, see:
https://packaging.python.org/guides/distributing-packages-using-setuptools/
"""
# -*- encoding: utf-8 -*-
from __future__ import absolute_import, print_function
import setuptools

# Keywords to improve package discoverability on PyPI
keywords = ["JWE", "KMS", "Secret Manager", "Encryption", "AWS", "Cryptography"]

# Reading long description from README.md
with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setuptools.setup(
    name="jwe-encryptify",
    version="0.0.1",
    author="M Santhosh Kumar",
    author_email="santhoshse7en@gmail.com",
    description=(
        "A Python package to facilitate JSON Web Encryption (JWE) with enhanced security, "
        "leveraging AWS Key Management Service (KMS) and Secrets Manager for secure "
        "input and output handling."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords=keywords,
    install_requires=[
        "jwcrypto",  # For JSON Web Encryption handling
        "boto3",     # AWS SDK to interact with KMS and Secrets Manager
        "botocore",  # AWS core library used by boto3
    ],
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.11",  # Specify a minimum Python version
    project_urls={  # Additional URLs for the project
        "Documentation": "https://github.com/santhoshse7en/jwe-encryptify#readme",
        "Source": "https://github.com/santhoshse7en/jwe-encryptify",
        "Tracker": "https://github.com/santhoshse7en/jwe-encryptify/issues",
    },
)
