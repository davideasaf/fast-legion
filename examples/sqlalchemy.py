"main.py"

from datetime import datetime
from typing import List, Optional

from fastapi import Depends, FastAPI
from pydantic import BaseModel
from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from fast_legion import (
    Legion,
    LegionConfig,
    RolesAccepted,
    RolesRequired,
    get_current_user,
    hash_password,
)

engine = create_engine(
    "sqlite:///sqlalchemy-example.db", connect_args={"check_same_thread": False},
)

Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """[summary]
    Generator function for dependency injection to fetch a 
    new sesesion on a new request
    """
    db = Session()
    try:
        yield db
    finally:
        db.close()


Base = declarative_base()

# A generic user model that might be used by an app powered by flask-praetorian
class DBUser(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True)
    password = Column(String(255))
    roles = Column(String(255))
    is_active = Column(Boolean, default=True, server_default="true")
    created_datetime = Column(DateTime(), nullable=False, server_default=func.now())

    def __repr__(self):
        return f"<User {self.user_id} - {self.username}>"


class UserBase(BaseModel):
    user_id: Optional[str] = None
    username: Optional[str] = None
    roles: Optional[str] = None
    is_active: Optional[bool] = None
    created_datetime: Optional[datetime] = None


api = FastAPI(title="SQLAlchemy API Demo for Fast Legion")


@api.on_event("startup")
async def startup_event():
    Base.metadata.create_all(bind=engine)

    db_session: Session = next(get_db())

    db_session.add_all(
        [
            DBUser(
                user_id=1,
                username="developer",
                password=hash_password("password", hash_alg="pbkdf2_sha512"),
                roles="admin,developer",
            ),
            DBUser(
                user_id=2,
                username="admin",
                password=hash_password("password", hash_alg="pbkdf2_sha512"),
                roles="admin",
            ),
            DBUser(
                user_id=3,
                username="user",
                password=hash_password("password", hash_alg="pbkdf2_sha512"),
            ),
        ]
    )

    db_session.commit()


@api.on_event("shutdown")
async def shutdown_event():
    Base.metadata.drop_all(bind=engine)


def lookup_by_username(username) -> Optional[DBUser]:
    db_session = next(get_db())
    return db_session.query(DBUser).filter(DBUser.username == username).first()


def lookup_by_id(id) -> Optional[DBUser]:
    db_session = next(get_db())
    return db_session.query(DBUser).filter(DBUser.user_id == id).first()


def get_user_rolenames(user: DBUser) -> List[str]:
    return user.roles


def get_user_password_hash(user: DBUser) -> str:
    return user.password


def get_user_id(user: DBUser) -> str:
    return user.user_id


Legion(
    api,
    lookup_by_username=lookup_by_username,
    lookup_by_id=lookup_by_id,
    get_user_rolenames=get_user_rolenames,
    get_user_password_hash=get_user_password_hash,
    get_user_id=get_user_id,
    config=LegionConfig(),
)


@api.get("/")
def hello_world():
    return "Hello world!"


@api.get("/protected")
def hello_world_protected(current_user: DBUser = Depends(get_current_user)):
    return "Hello world! You are in a protected route!"


@api.get("/protected-with-accepted-roles")
def hello_world_protected_accepted_roles(
    current_user: DBUser = Depends(RolesAccepted(["admin"])),
):
    return "Hello world! You are in a roles accepted protected route!"


@api.get("/protected-with-required-roles")
def hello_world_protected_required_roles(
    current_user: DBUser = Depends(RolesRequired(["admin", "developer"]))
):
    return "Hello world! You are in a roles required protected route!"
