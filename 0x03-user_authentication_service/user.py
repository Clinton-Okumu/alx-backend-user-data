#!/usr/bin/env python3
"""
Defines the User model for a SQLAlchemy ORM mapping to the 'users' table.
"""

from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    """
    User model mapped to the 'users' table with attributes:
    """
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)


if __name__ == "__main__":
    engine = create_engine('sqlite:///a.db:', echo=True)
    Base.metadata.create_all(engine)
