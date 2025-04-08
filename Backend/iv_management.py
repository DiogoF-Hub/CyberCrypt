import os


def generate_iv():
    return os.urandom(16)
