#!/usr/bin/env python3
"""This module contains a class
that inherits from Auth class
"""
import base64
from api.v1.auth.auth import Auth
from models.user import User
from typing import  TypeVar


class BasicAuth(Auth):
    """Inherits from Auth class
    and implements basic authentication
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Returns Base64 encoded authorization header"""
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith('Basic '):
            return None
        parts = authorization_header.split(' ')
        return parts[1]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str) -> str:
        """Decodes Base64 encoded authorization header"""
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            return base64.b64decode(base64_authorization_header).decode('utf-8')
        except ValueError:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):
        """Returns username and password from decoded Base64 encoded authorization header"""
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        parts = decoded_base64_authorization_header.split(':', 1)
        if len(parts) >= 2:
            username = parts[0]
            password = parts[1]
            return username, password
        else:
            return None, None

    def user_object_from_credentials(self,
                                     user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """Returns User object from user email and password"""
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        try:
            list_obj = User().search({'email': user_email})
            user_obj = list_obj[0] if list_obj else None
            if user_obj is None:
                return None
            if user_obj.is_valid_password(user_pwd):
                return user_obj
        except FileNotFoundError:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns the current user from the authorization header"""
        authorization_header = self.authorization_header(request)
        base64_authorization_header = self.extract_base64_authorization_header(authorization_header)
        decoded_base64_authorization_header = self.decode_base64_authorization_header(base64_authorization_header)
        user_email, user_pwd = self.extract_user_credentials(decoded_base64_authorization_header)
        return self.user_object_from_credentials(user_email, user_pwd)