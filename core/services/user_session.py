# core > services > user_session.py

from core.models.user_session import UserSessionTable
from core.schemas import UserSessionData
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timezone, timedelta
import logging

logger = logging.getLogger(__name__)


class UserSession:
    """
    Business logic for managing user sessions.

    Attributes:
        user_session (UserSessionTable): The UserSessionTable instance representing the session data.

    Methods:
        get_current_session(db, user_id, refresh_token): Retrieve the active session for a given user.
        create_session(db, session_data): Create a new user session.
        delete(db): Delete the specified user session.
        update_heartbeat(db): Update the heartbeat timestamp for the session.
        delete_expired_sessions(db): Delete all sessions that have expired.
    """

    def __init__(self, user_session: UserSessionTable):
        """
        Initialize a UserSession instance with a UserSessionTable object.

        Args:
            user_session (UserSessionTable): The UserSessionTable instance containing session data
                                             to be managed by this service class.
        """
        self.user_session = user_session

    @classmethod
    def get_current_session(cls, db: Session, user_id: int, refresh_token: str):
        """
        Retrieve the current user session based on user_id and refresh_token.

        This method queries the database to find an active session associated
        with a specific user identified by user_id and validated by a given
        refresh token. If a session is found, it returns an instance of the
        service class wrapping the session data.

        Args:
            db (Session): The active database session used for querying.
            user_id (int): The unique identifier of the user.
            refresh_token (str): The refresh token associated with the user's session.

        Returns:
            UserSession: An instance of the UserSession service class wrapping
                         the UserSessionTable object if a session is found, or None otherwise.
         """
        user_session = db.query(UserSessionTable).filter_by(user_id=user_id, refresh_token=refresh_token).first()
        return cls(user_session) if user_session else None

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

        expires_in_seconds = session_data.expires_in
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)

        try:
            # new_user_session = UserSessionTable(**session_data.__dict__)
            new_user_session = UserSessionTable(user_id=session_data.user_id,
                                                ip_address=session_data.ip_address,
                                                user_agent=session_data.user_agent,
                                                accept_language=session_data.accept_language,
                                                refresh_token=session_data.refresh_token,
                                                expires_at=expires_at)

            db.add(new_user_session)
            db.commit()
            logger.info(f'UserSession created: {new_user_session}')
            return cls(new_user_session)
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
            db.delete(self.user_session)
            db.commit()
            logger.info(f'UserSession deleted: {self.user_session}')
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
            self.user_session.last_heartbeat_at = datetime.now(timezone.utc)
            db.commit()
            logger.info(f'Heartbeat updated for session: {self.user_session}')
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
            expired_user_sessions = db.query(UserSessionTable).filter(UserSessionTable.expires_at <= now).all()
            for user_session in expired_user_sessions:
                db.delete(user_session)
            db.commit()
            logger.info(f'{len(expired_user_sessions)} expired sessions deleted')
        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f'Failed to delete expired sessions: {e}')
            raise

    def __repr__(self) -> str:
        return f'UserSession(user_id={self.user_session.user_id}, ip_address={self.user_session.ip_address})'