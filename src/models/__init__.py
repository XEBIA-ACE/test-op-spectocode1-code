"""
Models package.

Exports the SQLAlchemy Base and all ORM models so that Alembic
and application code can import them from a single location.

Usage:
    from src.models import Base, User
"""

from src.models.user import Base, User

__all__ = ["Base", "User"]
