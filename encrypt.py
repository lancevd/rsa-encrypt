import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def encrypt(plain_text, public_key):
    # Encrypt the plain text using the public key
    cipher_text = public_key.encrypt(
        plain_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_text

# Generate a public/private key pair
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Save the private key to a file
with open('private.pem', 'wb') as key_file:
    key_file.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Get the public key
public_key = key.public_key()

# Define the plain text
plain_text = b'Hello, World!'
plain_text_2 = b'My first program'

# Encrypt the plain text
cipher_text = encrypt(plain_text, public_key)
cipher_text_2 = encrypt(plain_text_2, public_key)

# Encode the cipher text using base64
cipher_text_base64 = base64.b64encode(cipher_text)
cipher_text_2_base64 = base64.b64encode(cipher_text_2)



# Save the base64 encoded cipher text to a file
with open('cipher_text1.txt', 'wb') as encrypted:
    encrypted.write(cipher_text_base64)
with open('cipher_text2.txt', 'wb') as encrypted:
    encrypted.write(cipher_text_2_base64)

# print(cipher_text_base64.decode())
