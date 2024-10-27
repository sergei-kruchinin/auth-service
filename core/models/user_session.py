# core > models > user_session.py

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from .base import Base


class UserSessionTable(Base):
    """
    Represents a user session in the application.

    Table structure for storing user session data.

    Attributes:
        id (int): The unique identifier for the session.
        user_id (int): The ID of the user associated with the session.
        user (User): The User object associated with the session (represented by a foreign key relationship).
        ip_address (str): The IP address from which the user has accessed the session, supporting both IPv4 and IPv6.
        user_agent (str): The user agent string of the user's browser or device.
        accept_language (str, optional): The languages accepted by the user's browser.
        refresh_token (str): A unique token used to refresh the session; must be unique across sessions.
        created_at (datetime): The timestamp when the session was created, automatically set to the current time.
        expires_at (datetime): The timestamp when the session expires, defined at session creation.
        last_heartbeat_at (datetime): The timestamp of the last heartbeat or active check-in, automatically updated.
    """

    __tablename__ = 'user_sessions'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user = relationship("User", back_populates="sessions")
    ip_address = Column(String(45), nullable=False)
    user_agent = Column(String(256), nullable=False)
    accept_language = Column(String(256), nullable=True)
    refresh_token = Column(String(512), nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_heartbeat_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return f'UserSession(user_id={self.user_id}, ip_address={self.ip_address})'
