# core > models > user.py

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func, Boolean
from sqlalchemy.orm import relationship
from .base import Base


class UserTable(Base):
    """
    Represents a user in the application.

    Attributes:
        id (int): The unique identifier for the user.
        username (str): The username name of the user.
        first_name (str): The first name of the user (optional).
        last_name (str): The last name of the user (optional).
        secret (str): The password hash or secret for the user (optional).
        is_admin (bool): Flag indicating whether the user has admin privileges.
        source (str): The source from which the user was created (e.g., 'manual', 'oauth') (optional).
        oa_id (str): The OAuth ID for the user (optional).
        created_at (datetime): The timestamp when the user was created.
        updated_at (datetime): The timestamp when the user was last updated.
    """

    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(128), unique=True, nullable=False)
    first_name = Column(String(128), nullable=True)
    last_name = Column(String(128), nullable=True)
    secret = Column(String(256), nullable=True)
    is_admin = Column(Boolean, nullable=False)
    source = Column(String(50), nullable=True)
    oa_id = Column(String(256), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True),
        onupdate=func.now()
    )

    sessions = relationship("UserSessionTable", back_populates="user")


    def __repr__(self) -> str:
        """
        Represent user information for debugging/logging.

        Returns:
            str: Representation of the user's username.
        """

        return f'<User(username={self.username}, id={self.id}, is_admin={self.is_admin})>'
