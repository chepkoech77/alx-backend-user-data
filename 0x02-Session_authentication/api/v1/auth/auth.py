#!/usr/bin/env python3
"""This is a parent class
for authorization
"""
from os import getenv
from flask import request
from typing import List, TypeVar


_my_session_id = getenv('SESSION_NAME')


class Auth:
    """This is a template for authorization"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Checks if the path is included"""
        if path is None:
            return True
        if excluded_paths is None:
            return True
        if len(excluded_paths) == 0:
            return True

        if not path.endswith('/'):
            path += '/'

        for excluded_path in excluded_paths:
            if excluded_path.endswith('*'):
                if path.startswith(excluded_path[:-1]):
                    return False
            elif path == excluded_path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """extracts the authorization header from the request"""
        if request is None:
            return None
        if request.headers.get('Authorization') is None:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """returns the current user from the authorization header"""
        return None

    def session_cookie(self, request=None):
        """returns the session cookie from the request"""
        if request is None:
            return None
        if request.cookies.get(_my_session_id) is None:
            return None
        return request.cookies.get(_my_session_id)
