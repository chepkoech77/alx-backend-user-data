#!/usr/bin/env python3
"""This module has a class that implements session Authentication"""
import uuid
from api.v1.auth.auth import Auth


class SessionAuth(Auth):
    """Inherits from Auth class
    and implements session authentication
    """
    
    user_id_by_session_id = {}

    def create_session(self, user_id: str) -> str:
        """Creates a session id for user id"""
        if user_id is None or not isinstance(user_id, str):
            return None
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str) -> str:
        """Returns user id for given session id"""
        if session_id is None:
            return None
        if session_id is not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """Returns the current user from the session cookie"""
        session_cookie = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_cookie)
        if user_id is None:
            return None
        return user_id