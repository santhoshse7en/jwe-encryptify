# jwe-encryptify

`jwe-encryptify` is a Python package designed for secure encryption and decryption using 
JSON Web Encryption (JWE), enhanced by AWS Key Management Service (KMS) and AWS Secrets Manager 
integration. This package offers a straightforward solution for handling sensitive data, allowing 
encrypted data exchange while securely managing encryption keys through AWS

## Features

* **Robust Data Encryption**: Uses JSON Web Encryption (JWE) to ensure data security and integrity.
* **AWS KMS Integration**: Leverages AWS KMS for secure key encryption and decryption.
* **AWS Secrets Manager**: Efficiently manages public and private key pairs for encryption processes.
* **User-Friendly API**: Simplified methods for secure JSON payload encryption and decryption.

## Installation

You can install the package via `pip` from PyPI:

```bash
pip install jwe-encryptify
```

## Usage

* **AWS Configuration**: Ensure that your AWS credentials and region are set up. The package requires AWS permissions to access KMS and Secrets Manager.
* **Environment Variable**: Set `AWS_DEFAULT_REGION` as an environment variable or configure it in your AWS settings.

## Encrypting Data

Use the `encrypt` method to secure JSON data with a public key stored in AWS Secrets Manager.

```python
from jwe_encryptify import encrypt

# Sample data to encrypt
data_to_encrypt = {"user": "John Doe", "account_id": "123456"}

# Encrypt the data
encrypted_jwe = encrypt(
    kms_id="your-kms-key-id",
    secret_name="your-secret-name",
    secret_key="public-key",
    api_response=data_to_encrypt
)

print("Encrypted JWE token:", encrypted_jwe)
```

## Decrypting Data

Use the `decrypt` method to decrypt an encrypted JWE token using a private key from AWS Secrets Manager.

```python
from jwe_encryptify import decrypt

# JWE token to decrypt
jwe_token = "your-encrypted-jwe-token"

# Decrypt the data
decrypted_data = decrypt(
    kms_id="your-kms-key-id",
    secret_name="your-secret-name",
    secret_key="private-key",
    jwe_payload=jwe_token
)

print("Decrypted Data:", decrypted_data)
```

## AWS Permissions

To use jwe-encryptify, your AWS IAM role or user should have permissions to:

* Access the specified KMS key (`kms_id`) for encryption and decryption.
* Retrieve secrets from AWS Secrets Manager for the specified secret names.

## Dependencies

The package requires:

* `jwcrypto`: For JWE encoding and decoding.
* `boto3`: AWS SDK for Python, used to interact with KMS and Secrets Manager.
* `botocore`: Core functionality required by `boto3`.

## License

This project is licensed under the MIT License.


## Contributing

We welcome contributions! Feel free to submit issues or pull requests to help improve the package.

## Authors
M Santhosh Kumar
Initial work
santhoshse7en@gmail.com


