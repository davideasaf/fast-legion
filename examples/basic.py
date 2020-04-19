"Basic Example"

from typing import List, Optional

from fastapi import Depends, FastAPI

from fast_legion import (
    Legion,
    LegionConfig,
    RolesAccepted,
    RolesRequired,
    get_current_user,
    hash_password,
)

api = FastAPI(title="Basic API Demo for Fast Legion")

user_list = [
    {
        "id": 1,
        "username": "developer",
        "password": hash_password("password", hash_alg="pbkdf2_sha512"),
        "roles": ["admin", "developer"],
    },
    {
        "id": 2,
        "username": "admin",
        "password": hash_password("password", hash_alg="pbkdf2_sha512"),
        "roles": ["admin"],
    },
    {
        "id": 3,
        "username": "user",
        "password": hash_password("password", hash_alg="pbkdf2_sha512"),
        "roles": [],
    },
]


def lookup_by_username(username) -> Optional[dict]:
    for user in user_list:
        if user["username"] == username:
            return user
    return None


def lookup_by_id(id) -> Optional[dict]:
    for user in user_list:
        if user["id"] == id:
            return user
    return None


def get_user_rolenames(user: dict) -> List[str]:
    return user["roles"]


def get_user_password_hash(user: dict) -> str:
    return user["password"]


def get_user_id(user: dict) -> str:
    return user["id"]


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
def hello_world_protected(current_user: dict = Depends(get_current_user)):
    return "Hello world! You are in a protected route!"


@api.get("/protected-with-accepted-roles")
def hello_world_protected_accepted_roles(
    current_user: dict = Depends(RolesAccepted(["admin"])),
):
    return "Hello world! You are in a roles accepted protected route!"


@api.get("/protected-with-required-roles")
def hello_world_protected_required_roles(
    current_user: dict = Depends(RolesRequired(["admin", "developer"])),
):
    return "Hello world! You are in a roles required protected route!"
