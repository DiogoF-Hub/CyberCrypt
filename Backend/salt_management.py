import os


def generate_salt(length=16):
    """
    Generates a cryptographically secure random salt.

    Args:
        length (int): Length of the salt in bytes (default: 16 bytes).

    Returns:
        bytes: The generated salt.
    """
    return os.urandom(length)
