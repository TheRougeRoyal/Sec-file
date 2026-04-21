import hashlib
import secrets
from dataclasses import dataclass

from tinyec import registry
from tinyec.ec import Point


CURVE = registry.get_curve("brainpoolP256r1")


@dataclass
class EncryptedPayload:
    ciphertext: bytes
    ephemeral_public_key: str
    nonce_hex: str


def _point_to_str(point: Point) -> str:
    return f"{point.x}:{point.y}"


def _str_to_point(value: str) -> Point:
    x_str, y_str = value.split(":")
    return Point(CURVE, int(x_str), int(y_str))


def generate_key_pair() -> tuple[str, str]:
    private_int = secrets.randbelow(CURVE.field.n - 1) + 1
    public_point = private_int * CURVE.g
    return str(private_int), _point_to_str(public_point)


def _derive_keystream(shared_secret: Point, nonce: bytes, size: int) -> bytes:
    base = (
        str(shared_secret.x).encode("utf-8")
        + b"|"
        + str(shared_secret.y).encode("utf-8")
        + b"|"
        + nonce
    )

    blocks = []
    counter = 0
    while len(b"".join(blocks)) < size:
        blocks.append(hashlib.sha256(base + counter.to_bytes(4, "big")).digest())
        counter += 1

    return b"".join(blocks)[:size]


def encrypt_bytes(plain_bytes: bytes, receiver_public_key: str) -> EncryptedPayload:
    receiver_point = _str_to_point(receiver_public_key)
    ephemeral_private = secrets.randbelow(CURVE.field.n - 1) + 1
    ephemeral_public = ephemeral_private * CURVE.g
    shared_secret = ephemeral_private * receiver_point
    nonce = secrets.token_bytes(16)
    keystream = _derive_keystream(shared_secret, nonce, len(plain_bytes))
    ciphertext = bytes(a ^ b for a, b in zip(plain_bytes, keystream))
    return EncryptedPayload(
        ciphertext=ciphertext,
        ephemeral_public_key=_point_to_str(ephemeral_public),
        nonce_hex=nonce.hex(),
    )


def decrypt_bytes(
    ciphertext: bytes,
    receiver_private_key: str,
    ephemeral_public_key: str,
    nonce_hex: str,
) -> bytes:
    private_int = int(receiver_private_key)
    ephemeral_point = _str_to_point(ephemeral_public_key)
    shared_secret = private_int * ephemeral_point
    nonce = bytes.fromhex(nonce_hex)
    keystream = _derive_keystream(shared_secret, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, keystream))
