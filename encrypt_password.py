#!/usr/bin/env python3
"""
Password encryption and validation module
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hash a password using bcrypt with salt
    Args:
        password: The password to hash

    Returns:
        bytes: The salted, hashed password
    """
    # Convert the password string to bytes
    encoded = password.encode()
    # Generate the salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(encoded, salt)
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validate that the provided password matches the hashed password
    Args:
        hashed_password: The hashed password to check against
        password: The password to validate

    Returns:
        bool: True if password matches, False otherwise
    """
    # Convert the password string to bytes
    encoded = password.encode()
    # Check if the password matches
    return bcrypt.checkpw(encoded, hashed_password)
