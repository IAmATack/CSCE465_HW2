import pytest

from secure_record import seal, open_record


# ---------------------------------------------------------------------
# Test material
# ---------------------------------------------------------------------

K_G2N_ENC = bytes(range(32))
K_G2N_MAC = bytes(range(32, 64))

K_N2G_ENC = bytes(range(64, 96))
K_N2G_MAC = bytes(range(96, 128))

SESSION_ID = b"12345678"

GATEWAY_TO_NODE = 0
NODE_TO_GATEWAY = 1

MESSAGE_TYPE = 1

PLAINTEXT = b'{"action":"READ","path":"notes.txt"}'


def make_gateway_record(sequence=0):
    return seal(
        K_G2N_ENC,
        K_G2N_MAC,
        SESSION_ID,
        GATEWAY_TO_NODE,
        sequence,
        MESSAGE_TYPE,
        PLAINTEXT,
    )


# ---------------------------------------------------------------------
# 1. Valid bidirectional messages
# ---------------------------------------------------------------------

def test_valid_bidirectional_messages():
    gateway_record = seal(
        K_G2N_ENC,
        K_G2N_MAC,
        SESSION_ID,
        GATEWAY_TO_NODE,
        0,
        MESSAGE_TYPE,
        PLAINTEXT,
    )

    message_type, plaintext = open_record(
        K_G2N_ENC,
        K_G2N_MAC,
        SESSION_ID,
        GATEWAY_TO_NODE,
        0,
        gateway_record,
    )

    assert message_type == MESSAGE_TYPE
    assert plaintext == PLAINTEXT

    node_record = seal(
        K_N2G_ENC,
        K_N2G_MAC,
        SESSION_ID,
        NODE_TO_GATEWAY,
        0,
        MESSAGE_TYPE,
        PLAINTEXT,
    )

    message_type, plaintext = open_record(
        K_N2G_ENC,
        K_N2G_MAC,
        SESSION_ID,
        NODE_TO_GATEWAY,
        0,
        node_record,
    )

    assert message_type == MESSAGE_TYPE
    assert plaintext == PLAINTEXT


# ---------------------------------------------------------------------
# 2. Modified ciphertext
# ---------------------------------------------------------------------

def test_modified_ciphertext_is_rejected():
    record = bytearray(make_gateway_record())

    # Header = 15 bytes.
    # IV = 16 bytes.
    # Therefore ciphertext begins at byte 31.
    ciphertext_start = 15 + 16

    record[ciphertext_start] ^= 0x01

    with pytest.raises(ValueError, match="MAC"):
        open_record(
            K_G2N_ENC,
            K_G2N_MAC,
            SESSION_ID,
            GATEWAY_TO_NODE,
            0,
            bytes(record),
        )


# ---------------------------------------------------------------------
# 3. Modified authenticated header
# ---------------------------------------------------------------------

def test_modified_authenticated_header_is_rejected():
    record = bytearray(make_gateway_record())

    # Change the message type in the authenticated header.
    # Header layout:
    # version(1) || direction(1) || sequence(8) ||
    # message_type(1) || ciphertext_length(4)
    message_type_offset = 1 + 1 + 8

    record[message_type_offset] ^= 0x01

    with pytest.raises(ValueError, match="MAC"):
        open_record(
            K_G2N_ENC,
            K_G2N_MAC,
            SESSION_ID,
            GATEWAY_TO_NODE,
            0,
            bytes(record),
        )


# ---------------------------------------------------------------------
# 4. Replayed record
# ---------------------------------------------------------------------

def test_replayed_record_is_rejected():
    record = make_gateway_record(sequence=0)

    # First delivery succeeds.
    message_type, plaintext = open_record(
        K_G2N_ENC,
        K_G2N_MAC,
        SESSION_ID,
        GATEWAY_TO_NODE,
        0,
        record,
    )

    assert message_type == MESSAGE_TYPE
    assert plaintext == PLAINTEXT

    # Receiver has now advanced and expects sequence 1.
    # Replaying sequence 0 must fail.
    with pytest.raises(ValueError, match="sequence"):
        open_record(
            K_G2N_ENC,
            K_G2N_MAC,
            SESSION_ID,
            GATEWAY_TO_NODE,
            1,
            record,
        )


# ---------------------------------------------------------------------
# 5. Record reflected into the opposite direction
# ---------------------------------------------------------------------

def test_reflected_record_is_rejected():
    record = make_gateway_record(sequence=0)

    # Gateway -> node record is presented as if it were
    # a node -> gateway record.
    with pytest.raises(ValueError, match="direction"):
        open_record(
            K_G2N_ENC,
            K_G2N_MAC,
            SESSION_ID,
            NODE_TO_GATEWAY,
            0,
            record,
        )


# ---------------------------------------------------------------------
# 6. Invalid authentication material
# ---------------------------------------------------------------------

def test_record_with_wrong_mac_key_is_rejected():
    record = make_gateway_record()

    wrong_mac_key = b"X" * 32

    with pytest.raises(ValueError, match="MAC"):
        open_record(
            K_G2N_ENC,
            wrong_mac_key,
            SESSION_ID,
            GATEWAY_TO_NODE,
            0,
            record,
        )
