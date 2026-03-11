"""Scope model for permission management."""

from sqlalchemy import Boolean, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from agentauth.core.database import BaseModel


class Scope(BaseModel):
    """Permission scope definition.

    Scopes use dotted notation (e.g. 'files.read', 'email.send').
    Wildcard scopes (e.g. 'files.*') resolve to all matching sub-scopes.
    """

    __tablename__ = "scopes"
    __table_args__ = (UniqueConstraint("name", name="uq_scopes_name"),)

    name: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        index=True,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )
    category: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        default="general",
        index=True,
    )
    is_default: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
