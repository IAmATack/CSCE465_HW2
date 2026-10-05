from secure_record import seal, open_record


def main():
    # Test keys.
    # In the real protocol, these come from Task 2's KDF.
    k_enc = bytes(range(32))
    k_mac = bytes(range(32, 64))
    session_id = b"12345678"

    gateway_to_node = 0
    message_type = 1
    sequence = 0

    plaintext = b'{"action":"READ","path":"notes.txt"}'

    # ---------------------------------------------------------
    # 1. Create a protected record.
    # ---------------------------------------------------------
    record = seal(
        k_enc,
        k_mac,
        session_id,
        gateway_to_node,
        sequence,
        message_type,
        plaintext,
    )

    print("Record created.")
    print("Record length:", len(record))

    # ---------------------------------------------------------
    # 2. Open the valid record.
    # ---------------------------------------------------------
    received_type, received_plaintext = open_record(
        k_enc,
        k_mac,
        session_id,
        gateway_to_node,
        sequence,
        record,
    )

    assert received_type == message_type
    assert received_plaintext == plaintext

    print("Valid record: PASS")

    # ---------------------------------------------------------
    # 3. Try modifying the ciphertext.
    # ---------------------------------------------------------
    modified = bytearray(record)

    # Header is 15 bytes.
    # IV is the next 16 bytes.
    # Change one byte in the ciphertext.
    ciphertext_start = 15 + 16
    modified[ciphertext_start] ^= 1

    try:
        open_record(
            k_enc,
            k_mac,
            session_id,
            gateway_to_node,
            sequence,
            bytes(modified),
        )
        raise AssertionError("Modified ciphertext was accepted")
    except ValueError:
        print("Modified ciphertext: REJECTED (PASS)")

    # ---------------------------------------------------------
    # 4. Try replaying the same record.
    # ---------------------------------------------------------
    try:
        open_record(
            k_enc,
            k_mac,
            session_id,
            gateway_to_node,
            1,  # Receiver now expects sequence 1.
            record,
        )
        raise AssertionError("Replay was accepted")
    except ValueError:
        print("Replay: REJECTED (PASS)")

    # ---------------------------------------------------------
    # 5. Try the wrong direction.
    # ---------------------------------------------------------
    try:
        open_record(
            k_enc,
            k_mac,
            session_id,
            1,  # Opposite direction.
            sequence,
            record,
        )
        raise AssertionError("Wrong direction was accepted")
    except ValueError:
        print("Wrong direction: REJECTED (PASS)")

    print("\nAll basic Task 3 tests passed.")


if __name__ == "__main__":
    main()
