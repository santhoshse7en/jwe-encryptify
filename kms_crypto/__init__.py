import json
import os
from base64 import b64decode, b64encode

import boto3

# Constants
REGION_NAME = os.getenv("AWS_DEFAULT_REGION")

# Initialize AWS KMS client
kms_client = boto3.client("kms", region_name=REGION_NAME)


# Custom Exceptions
class KMSError(Exception):
    """Base exception class for KMS operations."""
    pass


class SecretRetrievalError(KMSError):
    """Exception raised for errors during secret retrieval."""
    pass


class KMSDecryptionError(KMSError):
    """Exception raised for errors during KMS decryption."""
    pass


def decrypt(kms_id: str, lambda_function_name: str, encrypted_value: str) -> str:
    """Decrypts a KMS-encrypted string."""
    try:
        # Call KMS to decrypt the Base64-encoded ciphertext
        decrypted_response = kms_client.decrypt(
            KeyId=kms_id,
            CiphertextBlob=b64decode(encrypted_value),  # Decode Base64-encoded ciphertext
            EncryptionContext={"LambdaFunctionName": lambda_function_name}  # Add encryption context
        )

        # Decode and parse the plaintext JSON response
        decrypted_value = json.loads(decrypted_response["Plaintext"].decode("utf-8"))
        return decrypted_value

    except Exception as e:
        # Raise custom exception on decryption error
        raise KMSDecryptionError(f"Decryption failed: {str(e)}") from e


def encrypt(kms_id: str, plaintext: str) -> str:
    """Encrypts a plaintext string with KMS."""
    try:
        # Call KMS to encrypt the plaintext
        response = kms_client.encrypt(
            KeyId=kms_id,
            Plaintext=plaintext.encode("utf-8")  # Convert plaintext to bytes
        )

        # Base64 encode the ciphertext for safe storage
        ciphertext = b64encode(response["CiphertextBlob"]).decode("utf-8")
        return ciphertext

    except Exception as e:
        # Raise custom exception on encryption error
        raise KMSError(f"Encryption failed: {str(e)}") from e
