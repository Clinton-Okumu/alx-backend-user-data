#!/usr/bin/env python3
"""
BasicAuth module for handling basic authentication.

This module defines the BasicAuth class, which includes methods for extracting
and decoding the Base64-encoded part of an Authorization header following
Basic Authentication.
"""

import base64
from typing import TypeVar
from models.user import User


class BasicAuth:
    """
    BasicAuth class for handling basic authentication.
    
    Provides methods to extract and decode the Base64 part of an Authorization header.
    """

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """
        Extracts the Base64 part of the Authorization header for Basic Auth.

        Args:
            authorization_header (str): The Authorization header.

        Returns:
            str: The Base64 part of the Authorization header if valid, None otherwise.
        """
        if authorization_header is None:
            return None

        if not isinstance(authorization_header, str):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header[len("Basic "):]

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """
        Decodes a Base64 string.

        Args:
            base64_authorization_header (str): The Base64 string to decode.

        Returns:
            str: The decoded string in UTF-8 if valid, None otherwise.
        """
        if base64_authorization_header is None:
            return None

        if not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):
        """
        Extracts the user email and password from a decoded Base64 string.

        Args:
            decoded_base64_authorization_header (str): The decoded Base64 string.

        Returns:
            (str, str): A tuple with the user email and password, or (None, None)
                        if input is invalid.
        """
        # Check if decoded_base64_authorization_header is None
        if decoded_base64_authorization_header is None:
            return None, None

        # Check if decoded_base64_authorization_header is a string
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None

        # Check if decoded_base64_authorization_header contains a colon
        if ':' not in decoded_base64_authorization_header:
            return None, None

        # Split the string at the colon and return the email and password
        user_email, password = decoded_base64_authorization_header.split(':', 1)
        return user_email, password

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):
            """
            Returns the User instance based on the provided email and password.

            Args:
                user_email (str): The user's email.
                user_pwd (str): The user's password.

            Returns:
                User: The User instance if found and password is correct, None otherwise.
            """
            # Check if user_email and user_pwd are valid strings
            if not isinstance(user_email, str) or not isinstance(user_pwd, str):
                return None

            # Search for the user in the database using email
            users = User.search({"email": user_email})
            
            # If no user found, return None
            if not users:
                return None

            # Retrieve the first user found (assumption: email is unique)
            user = users[0]

            # Validate the password
            if not user.is_valid_password(user_pwd):
                return None

            return user
    
    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the User instance for a request based on Basic Authentication.

        Args:
            request: The Flask request object.

        Returns:
            User: The User instance if authentication is successful, None otherwise.
        """
        # Step 1: Get the Authorization header
        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None

        # Step 2: Extract the Base64 part of the Authorization header
        base64_auth = self.extract_base64_authorization_header(auth_header)
        if base64_auth is None:
            return None

        # Step 3: Decode the Base64 string
        decoded_auth = self.decode_base64_authorization_header(base64_auth)
        if decoded_auth is None:
            return None

        # Step 4: Extract the user email and password
        user_email, user_pwd = self.extract_user_credentials(decoded_auth)
        if user_email is None or user_pwd is None:
            return None

        # Step 5: Retrieve the User instance based on email and password
        user = self.user_object_from_credentials(user_email, user_pwd)
        return user
    
    