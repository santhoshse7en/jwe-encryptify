import base64
import json
import os

import boto3
from jwcrypto import jwk, jwe

# Define constants for encryption algorithms and region
ALGORITHM_KEY_ENC = "RSA-OAEP-256"
ALGORITHM_CONTENT_ENC = "A256GCM"
REGION_NAME = os.getenv("AWS_DEFAULT_REGION")

# Initialize AWS clients for Secrets Manager and KMS
secret_manager_client = boto3.client("secretsmanager", region_name=REGION_NAME)
kms_client = boto3.client("kms", region_name=REGION_NAME)


class JWEError(Exception):
    """Base exception for JWE encryption/decryption errors."""
    pass


class SecretRetrievalError(JWEError):
    """Exception for errors during secret retrieval."""
    pass


class KMSDecryptionError(JWEError):
    """Exception for errors during KMS decryption."""
    pass


def encrypt(kms_id: str, secret_name: str, secret_key: str, api_response: dict) -> str:
    """Encrypt a dictionary into a JWE token using a public key."""
    try:
        # Retrieve and decrypt the public key from Secrets Manager
        secret_dict = __get_encrypted_secret(secret_name, secret_key)
        ciphertext = secret_dict.get(secret_key)
        if not ciphertext:
            raise SecretRetrievalError("Public key not found in the secret.")

        # Decrypt the public key using KMS
        public_key_pem = __decrypt_kms_ciphertext(kms_id, ciphertext)
        if not public_key_pem:
            raise KMSDecryptionError("Failed to retrieve public key.")

        # Convert the public key to JWK format
        public_key = jwk.JWK.from_pem(public_key_pem.encode("utf-8"))

        # Encrypt the API response into a JWE token
        jwe_token = jwe.JWE(
            plaintext=json.dumps(api_response).encode("utf-8"),
            recipient=public_key,
            protected={
                "alg": ALGORITHM_KEY_ENC,
                "enc": ALGORITHM_CONTENT_ENC
            }
        )
        return jwe_token.serialize(compact=True)

    except (SecretRetrievalError, KMSDecryptionError) as e:
        raise JWEError(f"Encryption failed: {str(e)}")
    except Exception as e:
        raise JWEError(f"An unexpected error occurred during encryption: {str(e)}")


def decrypt(kms_id: str, secret_name: str, secret_key: str, jwe_payload: str) -> dict:
    """Decrypt a JWE payload using a private key from AWS Secrets Manager."""
    try:
        # Retrieve and decrypt the private key from Secrets Manager
        secret_dict = __get_encrypted_secret(secret_name, secret_key)
        ciphertext = secret_dict.get(secret_key)
        if not ciphertext:
            raise SecretRetrievalError("Private key not found in the secret.")

        # Decrypt the private key using KMS
        private_key_pem = __decrypt_kms_ciphertext(kms_id, ciphertext)
        if not private_key_pem:
            raise KMSDecryptionError("Failed to retrieve private key.")

        # Convert the private key to JWK format
        private_key = jwk.JWK.from_pem(private_key_pem.encode("utf-8"))

        # Decrypt the JWE token
        jwe_token = jwe.JWE()
        jwe_token.deserialize(jwe_payload, key=private_key)
        return json.loads(jwe_token.payload.decode("utf-8"))

    except (SecretRetrievalError, KMSDecryptionError) as e:
        raise JWEError(f"Decryption failed: {str(e)}")
    except Exception as e:
        raise JWEError(f"An unexpected error occurred during decryption: {str(e)}")


def __get_encrypted_secret(secret_name: str, secret_key: str) -> dict:
    """Retrieve and parse the secret from AWS Secrets Manager."""
    try:
        # Fetch secret value from Secrets Manager
        response = secret_manager_client.get_secret_value(SecretId=secret_name)
        secret_dict = json.loads(response.get("SecretString", '{}'))

        # Ensure the secret contains the required keys
        if not all(key in secret_dict for key in [secret_key, "private"]):
            raise SecretRetrievalError(f"Secret missing required keys: {secret_key} or 'private'.")

        return secret_dict

    except Exception as e:
        raise SecretRetrievalError(f"Error retrieving secret from Secrets Manager: {str(e)}")


def __decrypt_kms_ciphertext(kms_id: str, ciphertext: str) -> str:
    """Decrypt a ciphertext using AWS KMS."""
    try:
        # Decode the base64 ciphertext
        ciphertext_blob = base64.b64decode(ciphertext)

        # Decrypt the ciphertext using KMS
        response = kms_client.decrypt(CiphertextBlob=ciphertext_blob, KeyId=kms_id)
        return response["Plaintext"].decode("utf-8")

    except Exception as e:
        raise KMSDecryptionError(f"KMS decryption failed: {str(e)}")
