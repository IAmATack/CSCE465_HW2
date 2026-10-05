import struct

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Record format:
# header = version(1) || direction(1) || sequence(8) ||
#          message_type(1) || ciphertext_length(4)

VERSION = 1

HEADER_FORMAT = ">BBQBI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

SESSION_ID_SIZE = 8
SEQUENCE_SIZE = 8
IV_SIZE = 16

AES_KEY_SIZE = 32       # AES-256
MAC_KEY_SIZE = 32       # HMAC-SHA-256


def seal(
    k_enc,
    k_mac,
    session_id,
    direction,
    sequence,
    message_type,
    plaintext,
):
    """
    Encrypt and authenticate one record.

    Returns:
        complete record = header || iv || ciphertext || tag
    """

    # Basic input checks.
    if len(k_enc) != AES_KEY_SIZE:
        raise ValueError("AES key must be 32 bytes")

    if len(k_mac) != MAC_KEY_SIZE:
        raise ValueError("MAC key must be 32 bytes")

    if len(session_id) != SESSION_ID_SIZE:
        raise ValueError("session_id must be 8 bytes")

    if not (0 <= sequence <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError("sequence number out of range")

    if not (0 <= direction <= 255):
        raise ValueError("direction must fit in one byte")

    if not (0 <= message_type <= 255):
        raise ValueError("message_type must fit in one byte")

    # The assignment specifies:
    # IV = session_id(8 bytes) || sequence(8 bytes)
    iv = session_id + sequence.to_bytes(SEQUENCE_SIZE, "big")

    # AES-256-CTR encryption.
    cipher = Cipher(
        algorithms.AES(k_enc),
        modes.CTR(iv),
    )

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Build the authenticated header.
    header = struct.pack(
        HEADER_FORMAT,
        VERSION,
        direction,
        sequence,
        message_type,
        len(ciphertext),
    )

    # Encrypt-then-MAC:
    # HMAC(K_mac, header || iv || ciphertext)
    h = hmac.HMAC(k_mac, hashes.SHA256())
    h.update(header + iv + ciphertext)
    tag = h.finalize()

    return header + iv + ciphertext + tag


def open_record(
    k_enc,
    k_mac,
    session_id,
    expected_direction,
    expected_sequence,
    record,
):
    """
    Authenticate, validate, and decrypt one record.

    Returns:
        (message_type, plaintext)

    Raises ValueError on any invalid record.

    No plaintext is returned after an error.
    """

    if len(k_enc) != AES_KEY_SIZE:
        raise ValueError("AES key must be 32 bytes")

    if len(k_mac) != MAC_KEY_SIZE:
        raise ValueError("MAC key must be 32 bytes")

    if len(session_id) != SESSION_ID_SIZE:
        raise ValueError("session_id must be 8 bytes")

    # We need at least:
    # header + IV + HMAC tag
    if len(record) < HEADER_SIZE + IV_SIZE + 32:
        raise ValueError("Record is too short")

    # Parse only the fixed-size header first.
    header = record[:HEADER_SIZE]

    (
        version,
        direction,
        sequence,
        message_type,
        ciphertext_length,
    ) = struct.unpack(HEADER_FORMAT, header)

    # Check the version.
    if version != VERSION:
        raise ValueError("Unsupported record version")

    # Make sure the record has exactly the expected structure.
    expected_length = (
        HEADER_SIZE
        + IV_SIZE
        + ciphertext_length
        + 32  # HMAC-SHA-256 tag
    )

    if len(record) != expected_length:
        raise ValueError("Invalid record length")

    # Extract fields.
    offset = HEADER_SIZE

    iv = record[offset:offset + IV_SIZE]
    offset += IV_SIZE

    ciphertext = record[offset:offset + ciphertext_length]
    offset += ciphertext_length

    tag = record[offset:offset + 32]

    # Reconstruct the IV that should correspond to this
    # session and sequence number.
    expected_iv = (
        session_id
        + sequence.to_bytes(SEQUENCE_SIZE, "big")
    )

    if iv != expected_iv:
        raise ValueError("Invalid IV")

    # IMPORTANT:
    # Verify the MAC BEFORE decrypting.
    h = hmac.HMAC(k_mac, hashes.SHA256())
    h.update(header + iv + ciphertext)

    try:
        # cryptography's verify() performs the MAC comparison
        # using its constant-time verification mechanism.
        h.verify(tag)
    except Exception:
        raise ValueError("Invalid MAC")

    # The record is authenticated at this point.
    # Now enforce the expected direction and sequence number.
    if direction != expected_direction:
        raise ValueError("Wrong record direction")

    if sequence != expected_sequence:
        raise ValueError("Unexpected sequence number")

    # Only decrypt after all authentication checks succeed.
    cipher = Cipher(
        algorithms.AES(k_enc),
        modes.CTR(iv),
    )

    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return message_type, plaintext
