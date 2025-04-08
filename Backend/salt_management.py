import os


def generate_salt(length=16):
    return os.urandom(length)
