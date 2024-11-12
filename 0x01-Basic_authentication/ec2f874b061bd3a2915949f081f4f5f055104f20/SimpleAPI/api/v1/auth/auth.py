#!/usr/bin/env python3
"""
Auth module for handling authentication and access control.

This module provides a base `Auth` class to handle authorization, header
management, and current user identification. It defines methods for checking
if a path requires authentication, retrieving the authorization header, and
identifying the current user.
"""

from flask import request
from typing import List, TypeVar


class Auth:
    """
    Base class for authentication methods.

    Provides methods to determine if a path requires authentication, retrieve
    the authorization header, and obtain the current user.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if the specified path requires authentication.
        """
        if path is None:
            return True

        if not excluded_paths:
            return True

        # Normalize the path to ensure trailing slashes are consistent
        normalized_path = path if path.endswith('/') else path + '/'

        for excluded_path in excluded_paths:
            normalized_excluded_path = excluded_path if excluded_path.endswith('/') else excluded_path + '/'
            if normalized_path == normalized_excluded_path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the Authorization header from the request.
        """
        if request is None:
            return None

        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Placeholder method to retrieve the current user.
        """
        return None
