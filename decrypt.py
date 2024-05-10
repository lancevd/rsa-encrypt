import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def decrypt(cipher_text, private_key):
    # Decrypt the cipher texts using the private key
    plain_text = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain_text

# Load the private key from a file
with open('private.pem', 'rb') as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Load the base64 encoded cipher texts from a file
with open('cipher_text1.txt', 'rb') as cipher_file:
    cipher_text_base64 = cipher_file.read()
with open('cipher_text2.txt', 'rb') as cipher_file2:
    cipher_text_2_base64 = cipher_file2.read()

# Decode the base64 encoded cipher texts
cipher_text = base64.b64decode(cipher_text_base64)
cipher_text_2 = base64.b64decode(cipher_text_2_base64)

# Decrypt the cipher texts
plain_text = decrypt(cipher_text, private_key)
plain_text2 = decrypt(cipher_text_2, private_key)

print(plain_text.decode())
print(plain_text2.decode())

