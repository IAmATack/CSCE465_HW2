from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


# ---------------------------------------------------------
# AES-CTR helper functions
# ---------------------------------------------------------

def encrypt(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ---------------------------------------------------------
# Receiver
# ---------------------------------------------------------

def receiver(key, iv, ciphertext):
    plaintext = decrypt(key, iv, ciphertext)

    print(f"Receiver processed: {plaintext.decode()}")


# ---------------------------------------------------------
# Main experiment
# ---------------------------------------------------------

def main():
    # Generate a random 256-bit AES key.
    key = os.urandom(32)

    # AES has a 128-bit block size, so CTR uses a 16-byte IV.
    iv = os.urandom(16)

    # Fixed-length command from the assignment.
    original = b'{"action":"READ","path":"notes.txt"}'

    print("Original plaintext:")
    print(original.decode())

    # Encrypt the command.
    ciphertext = encrypt(key, iv, original)

    print("\nOriginal ciphertext:")
    print(ciphertext.hex())

    # -----------------------------------------------------
    # Attacker performs a CTR bit-flipping attack.
    #
    # We want to change READ -> WRITE.
    # Both strings must have the same length.
    # -----------------------------------------------------

    desired = b'{"action":"LIST","path":"notes.txt"}'

    # Check that the messages are exactly the same length.
    assert len(original) == len(desired)

    # Calculate the XOR difference between the two plaintexts.
    xor_mask = bytes(
        original_byte ^ desired_byte
        for original_byte, desired_byte in zip(original, desired)
    )

    # The attacker modifies the ciphertext using the XOR mask.
    modified_ciphertext = bytes(
        ciphertext_byte ^ mask_byte
        for ciphertext_byte, mask_byte in zip(ciphertext, xor_mask)
    )

    print("\nXOR mask:")
    print(xor_mask.hex())

    print("\nModified ciphertext:")
    print(modified_ciphertext.hex())

    # -----------------------------------------------------
    # Receiver decrypts the attacker's modified ciphertext.
    # -----------------------------------------------------

    print("\nAfter ciphertext modification:")
    receiver(key, iv, modified_ciphertext)

    # -----------------------------------------------------
    # Replay attack
    #
    # The attacker sends the same valid ciphertext again.
    # There is no sequence number or MAC, so the receiver
    # has no mechanism to reject the replay.
    # -----------------------------------------------------

    print("\nReplay attack:")
    receiver(key, iv, ciphertext)
    receiver(key, iv, ciphertext)


if __name__ == "__main__":
    main()

