"""
User data model for the registration feature.

Supports:
- Email-based account creation
- Password hashing (bcrypt-compatible)
- Email verification status tracking
- Timestamps for auditing

Compatible with SQLAlchemy ORM and Alembic migrations.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class User(Base):
    """
    Represents a registered user account.

    Fields added / updated for the registration feature:
    - email                 : unique identifier used for login and verification
    - password_hash         : bcrypt hash of the user's password (never store plaintext)
    - is_email_verified     : tracks whether the user has confirmed their email address
    - email_verification_token : one-time token sent in the verification email
    - email_verification_sent_at : timestamp of the last verification email dispatch
    - created_at / updated_at   : audit timestamps
    """

    __tablename__ = "users"

    # Primary key — UUID avoids sequential enumeration attacks
    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
        index=True,
    )

    # --- Core registration fields ---

    # Email must be unique; stored in lowercase to prevent duplicate accounts
    email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    # Bcrypt hash of the user's password (60-char output for bcrypt)
    password_hash = Column(
        String(128),
        nullable=False,
    )

    # --- Email verification fields (new for registration feature) ---

    # False until the user clicks the link in the verification email
    is_email_verified = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )

    # Opaque token included in the verification email link; cleared after use
    email_verification_token = Column(
        String(128),
        nullable=True,
        unique=True,
        index=True,
    )

    # When the most recent verification email was dispatched (rate-limiting helper)
    email_verification_sent_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # --- Audit timestamps ---

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default="now()",
    )

    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        server_default="now()",
    )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def mark_email_verified(self) -> None:
        """
        Mark the user's email as verified and clear the one-time token.
        Call this after successfully validating the verification token.
        """
        self.is_email_verified = True
        self.email_verification_token = None
        self.email_verification_sent_at = None
        self.updated_at = datetime.now(timezone.utc)

    def __repr__(self) -> str:
        return (
            f"<User id={self.id!r} email={self.email!r} "
            f"is_email_verified={self.is_email_verified!r}>"
        )
