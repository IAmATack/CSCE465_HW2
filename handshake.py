import hashlib
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa
from cryptography.hazmat.primitives.hmac import HMAC


# ---------------------------------------------------------
# Transcript encoding
# ---------------------------------------------------------

FIELD_SIZE = 384
PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_LABEL = b"ffdhe3072"


def encode_dh_public_key(public_key):
    """Encode a DH public value as exactly 384 bytes."""
    value = public_key.public_numbers().y
    return value.to_bytes(FIELD_SIZE, byteorder="big")


def encode_field(value):
    """Encode one transcript field with a 4-byte big-endian length."""
    return struct.pack(">I", len(value)) + value


def build_transcript(
    gateway_identity,
    node_identity,
    gateway_public_key,
    node_public_key,
    gateway_nonce,
    node_nonce,
):
    gateway_dh = encode_dh_public_key(gateway_public_key)
    node_dh = encode_dh_public_key(node_public_key)

    fields = [
        PROTOCOL_LABEL,
        GROUP_LABEL,
        gateway_identity,
        node_identity,
        gateway_dh,
        node_dh,
        gateway_nonce,
        node_nonce,
    ]

    return b"".join(encode_field(field) for field in fields)


# ---------------------------------------------------------
# RSA-PSS authentication
# ---------------------------------------------------------

def sign_transcript(private_key, role, transcript_hash):
    """Sign role || SHA-256(transcript) using RSA-PSS/SHA-256."""
    message = role + transcript_hash

    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_transcript(public_key, role, transcript_hash, signature):
    """Return True only if the RSA-PSS signature is valid."""
    message = role + transcript_hash

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True

    except Exception:
        return False


# ---------------------------------------------------------
# Assignment-specific KDF
# ---------------------------------------------------------

def hmac_sha256(key, data):
    h = HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def derive_keys(shared_secret, transcript):
    """
    Derive the assignment-specified session keys.

    Returns:
        K_g2n_enc
        K_g2n_mac
        K_n2g_enc
        K_n2g_mac
        session_id
    """

    # SHA-256(transcript)
    TH = hashlib.sha256(transcript).digest()

    # Z must be represented as exactly 384 bytes.
    Z_value = int.from_bytes(shared_secret, byteorder="big")
    Z = Z_value.to_bytes(FIELD_SIZE, byteorder="big")

    # K_master =
    # SHA-256("CSCE465-KDF-v1" || Z || TH)
    K_master = hashlib.sha256(
        b"CSCE465-KDF-v1" + Z + TH
    ).digest()

    K_g2n_enc = hmac_sha256(
        K_master,
        b"gateway-to-node encryption" + TH,
    )

    K_g2n_mac = hmac_sha256(
        K_master,
        b"gateway-to-node MAC" + TH,
    )

    K_n2g_enc = hmac_sha256(
        K_master,
        b"node-to-gateway encryption" + TH,
    )

    K_n2g_mac = hmac_sha256(
        K_master,
        b"node-to-gateway MAC" + TH,
    )

    session_id = hmac_sha256(
        K_master,
        b"session identifier" + TH,
    )[:8]

    return (
        K_g2n_enc,
        K_g2n_mac,
        K_n2g_enc,
        K_n2g_mac,
        session_id,
    )


# ---------------------------------------------------------
# Handshake
# ---------------------------------------------------------

def perform_handshake():
    # -----------------------------------------------------
    # Long-term identity/signing keys
    # -----------------------------------------------------

    gateway_signing_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    node_signing_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    gateway_public_signing_key = gateway_signing_key.public_key()
    node_public_signing_key = node_signing_key.public_key()

    # -----------------------------------------------------
    # Load the standardized ffdhe3072 parameters
    # -----------------------------------------------------

    with open("ffdhe3072.pem", "rb") as f:
        parameters = serialization.load_pem_parameters(f.read())

    # -----------------------------------------------------
    # Fresh ephemeral DH values for this session
    # -----------------------------------------------------

    gateway_dh_private = parameters.generate_private_key()
    node_dh_private = parameters.generate_private_key()

    gateway_dh_public = gateway_dh_private.public_key()
    node_dh_public = node_dh_private.public_key()

    # -----------------------------------------------------
    # Fresh nonces
    # -----------------------------------------------------

    gateway_nonce = os.urandom(16)
    node_nonce = os.urandom(16)

    gateway_identity = b"gateway"
    node_identity = b"node"

    # -----------------------------------------------------
    # Build canonical transcript
    # -----------------------------------------------------

    transcript = build_transcript(
        gateway_identity,
        node_identity,
        gateway_dh_public,
        node_dh_public,
        gateway_nonce,
        node_nonce,
    )

    TH = hashlib.sha256(transcript).digest()

    # -----------------------------------------------------
    # Both parties sign role || TH
    # -----------------------------------------------------

    gateway_signature = sign_transcript(
        gateway_signing_key,
        b"gateway",
        TH,
    )

    node_signature = sign_transcript(
        node_signing_key,
        b"node",
        TH,
    )

    # -----------------------------------------------------
    # Verify identities
    # -----------------------------------------------------

    if gateway_identity != b"gateway":
        raise ValueError("Unexpected gateway identity")

    if node_identity != b"node":
        raise ValueError("Unexpected node identity")

    # -----------------------------------------------------
    # Verify peer signatures
    # -----------------------------------------------------

    if not verify_transcript(
        gateway_public_signing_key,
        b"gateway",
        TH,
        gateway_signature,
    ):
        raise ValueError("Invalid gateway signature")

    if not verify_transcript(
        node_public_signing_key,
        b"node",
        TH,
        node_signature,
    ):
        raise ValueError("Invalid node signature")

    # -----------------------------------------------------
    # Calculate the Diffie-Hellman shared secret
    # -----------------------------------------------------

    gateway_shared = gateway_dh_private.exchange(node_dh_public)
    node_shared = node_dh_private.exchange(gateway_dh_public)

    if gateway_shared != node_shared:
        raise ValueError("DH shared secrets do not match")

    # -----------------------------------------------------
    # Derive session keys
    # -----------------------------------------------------

    gateway_keys = derive_keys(gateway_shared, transcript)
    node_keys = derive_keys(node_shared, transcript)

    if gateway_keys != node_keys:
        raise ValueError("Derived keys do not match")

    (
        K_g2n_enc,
        K_g2n_mac,
        K_n2g_enc,
        K_n2g_mac,
        session_id,
    ) = gateway_keys

    # -----------------------------------------------------
    # Display non-secret verification information
    # -----------------------------------------------------

    print("Handshake successful")
    print("Transcript hash:", TH.hex())
    print("Session ID:", session_id.hex())
    print("Gateway -> Node encryption key:", K_g2n_enc.hex())
    print("Gateway -> Node MAC key:", K_g2n_mac.hex())
    print("Node -> Gateway encryption key:", K_n2g_enc.hex())
    print("Node -> Gateway MAC key:", K_n2g_mac.hex())


if __name__ == "__main__":
    perform_handshake()

