from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RSA_KEY_SIZE = 2048

# OAEP con SHA-256 tanto para el hash como para MGF1.
_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def generate_keypair() -> rsa.RSAPrivateKey:
    """Genera un par RSA-2048. La clave publica se obtiene con .public_key()."""
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)


def public_key_to_bytes(public_key: rsa.RSAPublicKey) -> bytes:
    """Serializa la clave publica en PEM (SubjectPublicKeyInfo) para enviarla."""
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_from_bytes(data: bytes) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < RSA_KEY_SIZE:
        raise ValueError("Clave publica RSA invalida (se requieren >= 2048 bits)")
    return key


def rsa_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    return public_key.encrypt(plaintext, _OAEP)


def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return private_key.decrypt(ciphertext, _OAEP)
