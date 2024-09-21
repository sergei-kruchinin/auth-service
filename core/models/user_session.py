# core > models > user.py
from core.schemas import *
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import relationship, Session
from datetime import timezone
from .base import Base
import logging
logger = logging.getLogger(__name__)


class UserSession(Base):
    """
    Represents a user session in the application.

    Attributes:
        id (int): The unique identifier for the session.
        user_id (int): The ID of the user associated with the session.
        user (User): The User object associated with the session.
        ip_address (str): The IP address from which the user has accessed the session.
        user_agent (str): The user agent string of the user's browser or device.
        accept_language (str): The languages accepted by the user's browser (optional).
        refresh_token (str): A unique token used to refresh the session.
        created_at (datetime): The timestamp when the session was created.
        expires_at (datetime): The timestamp when the session expires.
        last_heartbeat_at (datetime): The timestamp of the last heartbeat or active check-in.
    """

    __tablename__ = 'user_sessions'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user = relationship("User", back_populates="sessions")
    ip_address = Column(String(45), nullable=False)  # IPv4/IPv6
    user_agent = Column(String(256), nullable=False)
    accept_language = Column(String(256), nullable=True)
    refresh_token = Column(String(512), nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_heartbeat_at = Column(DateTime(timezone=True), server_default=func.now())  # Поле для последнего heartbeat

    def __init__(self, session_data: UserSessionData):
        """
        Initialize a UserSession instance with session data.

        Args:
            session_data (UserSessionData): The data required to create a session.
        """
        self.user_id = session_data.user_id
        self.ip_address = session_data.ip_address
        self.user_agent = session_data.user_agent
        self.accept_language = session_data.accept_language
        self.refresh_token = session_data.refresh_token
        self.expires_at = session_data.expires_at

    def __repr__(self) -> str:
        return f'UserSession(user_id={self.user_id}, ip_address={self.ip_address})'

    @classmethod
    def get_current_session(cls, db: Session, user_id: int, refresh_token: str):
        """
        Get the current session by user_id and refresh_token.

        Args:
            db (Session): The database session.
            user_id (int): The ID of the user.
            refresh_token (str): The refresh token of the session.

        Returns:
            UserSession: The session object if found, None otherwise.
        """
        return db.query(cls).filter_by(user_id=user_id, refresh_token=refresh_token).first()

    @classmethod
    def create_session(cls, db: Session, session_data: UserSessionData):
        """
        Create a new session.

        Args:
            db (Session): The database session.
            session_data (UserSessionData): The data required to create a session.

        Returns:
            UserSession: The created session object.
        """
        try:
            session = cls(session_data)
            db.add(session)
            db.commit()
            logger.info(f'UserSession created: {session}')
            return session
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f'Failed to create session: {e}')
            raise

    def delete(self, db: Session):
        """
        Delete the current session.

        Args:
            db (Session): The database session.
        """
        try:
            db.delete(self)
            db.commit()
            logger.info(f'UserSession deleted: {self}')
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f'Failed to delete session: {e}')
            raise

    def update_heartbeat(self, db: Session):
        """
        Update the last heartbeat time of the current session.

        Args:
            db (Session): The database session.
        """
        try:
            self.last_heartbeat_at = datetime.now(timezone.utc)
            db.commit()
            logger.info(f'Heartbeat updated for session: {self}')
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f'Failed to update heartbeat: {e}')
            raise

    @classmethod
    def delete_expired_sessions(cls, db: Session):
        """
        Delete all expired sessions.

        Args:
            db (Session): The database session.
        """
        try:
            now = datetime.now(timezone.utc)
            expired_sessions = db.query(cls).filter(cls.expires_at <= now).all()
            for session in expired_sessions:
                db.delete(session)
            db.commit()
            logger.info(f'{len(expired_sessions)} expired sessions deleted')
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f'Failed to delete expired sessions: {e}')
            raise
