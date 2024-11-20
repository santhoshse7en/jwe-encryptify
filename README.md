# jwe-encryptify

`jwe-encryptify` is a Python package designed for secure encryption and decryption using
JSON Web Encryption (JWE), enhanced by AWS Key Management Service (KMS) and AWS Secrets Manager
integration. This package offers a straightforward solution for handling sensitive data, allowing
encrypted data exchange while securely managing encryption keys through AWS.

## Table of Contents

* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
    * [Encrypting Data using JWE](#encrypting-data-using-jwe)
    * [Encrypting Data using KMS](#encrypting-data-using-kms)
    * [Decrypting Data using JWE](#decrypting-data-using-jwe)
    * [Decrypting Data using KMS](#decrypting-data-using-kms)
* [AWS Permissions](#aws-permissions)
* [Dependencies](#dependencies)
* [License](#license)
* [Contributing](#contributing)
* [Authors](#authors)

## Features

* **Robust Data Encryption**: Uses JSON Web Encryption (JWE) to ensure data security and integrity.
* **AWS KMS Integration**: Leverages AWS KMS for secure key encryption and decryption.
* **AWS Secrets Manager**: Efficiently manages public and private key pairs for encryption
  processes.
* **User-Friendly API**: Simplified methods for secure JSON payload encryption and decryption.

## Installation

You can install the package via `pip` from PyPI:

```bash
pip install jwe-encryptify
```

## Usage

* **AWS Configuration**: Ensure that your AWS credentials and region are set up. The package
  requires AWS permissions to access KMS and Secrets Manager.
* **Environment Variable**: Set `AWS_DEFAULT_REGION` as an environment variable or configure it in
  your AWS settings.

## Encrypting Data using JWE

Use the `encrypt` method to secure JSON data with a public key stored in AWS Secrets Manager.

```python
from jwe_crypto import encrypt

# Data to encrypt
data_to_encrypt = {"user": "John Doe", "account_id": "123456"}

# Encrypt the data
jwe_encrypted_token = encrypt(
  kms_id="your-kms-key-id",  # AWS KMS key ID for encryption
  secret_name="your-secret-name",  # AWS Secrets Manager secret name
  secret_key="public-key",  # Key name in the secret (public key)
  api_response=data_to_encrypt  # JSON data to encrypt
)
print("Encrypted JWE Token:", jwe_encrypted_token)

```

## Encrypting Data using KMS

Use the `encrypt` method to secure JSON data using an AWS KMS key.

```python
from kms_crypto import encrypt

# Data to encrypt
data_to_encrypt = {"user": "John Doe", "account_id": "123456"}

# Encrypt the data using KMS
kms_encrypted_value = encrypt(
  kms_id="your-kms-key-id",  # AWS KMS key ID used for encryption
  plaintext=str(data_to_encrypt)  # Convert the JSON data to a string
)

print("Encrypted KMS Value:", kms_encrypted_value)

```

## Decrypting Data using JWE

Use the `decrypt` method to decrypt an encrypted JWE token using a private key from AWS Secrets
Manager.

```python
from jwe_crypto import decrypt

# JWE token to decrypt
jwe_token = "your-encrypted-jwe-token"

# Decrypt the data
decrypted_data = decrypt(
  kms_id="your-kms-key-id",  # AWS KMS key ID
  secret_name="your-secret-name",  # AWS Secrets Manager secret name
  secret_key="private-key",  # Key name in the secret (private key)
  jwe_payload=jwe_token  # Encrypted JWE payload
)

print("Decrypted Data:", decrypted_data)
```

## Decrypting Data using KMS

Use the `decrypt` method to decrypt an encrypted value using an AWS KMS key and encryption context.

```python
from kms_crypto import decrypt

# Encrypted value to decrypt
encrypted_value = "your-encrypted-kms-value"

# Decrypt the data using KMS
decrypted_data = decrypt(
  kms_id="your-kms-key-id",  # AWS KMS key ID used for decryption
  lambda_function_name="your-lambda-function-name",  # Encryption context
  encrypted_value=encrypted_value  # Encrypted value to decrypt
)

print("Decrypted Data:", decrypted_data)
```

## AWS Permissions

Ensure the following permissions are assigned to your AWS IAM role or user:

* KMS Permissions:
    * `kms:Encrypt`
    * `kms:Decrypt`
* Secrets Manager Permissions:
    * `secretsmanager:GetSecretValue`

## Dependencies

The package requires the following dependencies:

* [`jwcrypto`](https://pypi.org/project/jwcrypto/): For JWE encoding and decoding.
* [`boto3`](https://pypi.org/project/boto3/): AWS SDK for Python.
* [`botocore`](https://pypi.org/project/botocore/): Core library used by boto3.
  Install all dependencies automatically via pip install jwe-encryptify.

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Submit issues or pull requests to enhance the package. For major changes,
please open a discussion first.

## Authors

M Santhosh Kumar
Initial work
santhoshse7en@gmail.com


