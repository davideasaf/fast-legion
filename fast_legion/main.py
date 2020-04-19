from datetime import timedelta
from typing import Callable, Generic, List, Optional, Type, TypeVar, Union, Tuple
from typing_extensions import Protocol

import jwt
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt import PyJWTError
from pydantic import BaseModel
from starlette.status import HTTP_403_FORBIDDEN

from fast_legion.constants import (
    DEFAULT_ACCEPTED_JWT_DECODE_ALGS,
    DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES,
    DEFAULT_JWT_ENCODING_ALG,
    DEFAULT_LEGION_HASH_SCHEME,
    DEFAULT_LOGIN_ROUTE,
    DEFAULT_LOGIN_ROUTE_TAGS,
    DEFAULT_SECRET_KEY,
)
from fast_legion.schemas.token import Token, TokenPayload
from fast_legion.security_utils import create_access_token
from passlib.context import CryptContext

User = TypeVar("User")
Role = TypeVar("Role", bound=str)


class LegionConfig(BaseModel):
    ACCESS_TOKEN_EXPIRE_MINUTES: int = DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES
    SECRET_KEY: str = DEFAULT_SECRET_KEY
    LEGION_HASH_SCHEME: str = DEFAULT_LEGION_HASH_SCHEME
    ACCEPTED_JWT_DECODE_ALGS: List[str] = DEFAULT_ACCEPTED_JWT_DECODE_ALGS
    JWT_ENCODING_ALG: str = DEFAULT_JWT_ENCODING_ALG
    LOGIN_ROUTE: str = DEFAULT_LOGIN_ROUTE
    LOGIN_ROUTE_TAGS: List[str] = DEFAULT_LOGIN_ROUTE_TAGS


class LegionGlobal(BaseModel):
    legion_config: LegionConfig
    user_lookup_by_id: Callable
    get_user_rolenames: Callable
    lookup_by_username: Callable
    get_user_password_hash: Callable
    pwd_context: CryptContext

    class Config:
        arbitrary_types_allowed = True


# Making an explicit decision to not set to 'None'.
# Reasoning: the first function that is called ("Legion") sets this GLOBAL. Therefore it
# is expected to be there
LEGION_GLOBAL: LegionGlobal


def hash_password(
    password: str, password_context: CryptContext = None, *, hash_alg=None
):
    if password_context:
        return password_context.hash(password)

    if hash_alg:
        return CryptContext(schemes=[hash_alg], deprecated="auto").hash(password)

    raise Exception(
        "You must either provide a password context or hashing alg to hash a password"
    )


def Legion(
    app: FastAPI,
    *,
    get_user_rolenames: Callable[[User], List[Role]],
    get_user_password_hash: Callable[[User], str],
    lookup_by_username: Callable[[str], User],
    lookup_by_id: Callable[[Union[str, int]], User],
    get_user_id: Callable[[User], Union[str, int]],
    is_user_active: Optional[Callable[[User], bool]] = None,
    config: LegionConfig
):
    global LEGION_GLOBAL
    LEGION_GLOBAL = LegionGlobal(
        legion_config=config,
        user_lookup_by_id=lookup_by_id,
        get_user_rolenames=get_user_rolenames,
        lookup_by_username=lookup_by_username,
        get_user_password_hash=get_user_password_hash,
        pwd_context=CryptContext(
            schemes=[config.LEGION_HASH_SCHEME], deprecated="auto"
        ),
    )

    def verify_password(plain_password: str, hashed_password: str):
        return LEGION_GLOBAL.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(password: str):
        return LEGION_GLOBAL.pwd_context.hash(password)

    def authenticate_user(username: str, password: str) -> Optional[User]:
        user = LEGION_GLOBAL.lookup_by_username(username=username)
        if not user:
            return None
        if not verify_password(password, get_user_password_hash(user)):
            return None
        return user

    @app.post(config.LOGIN_ROUTE, response_model=Token, tags=config.LOGIN_ROUTE_TAGS)
    def login_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
        """
        OAuth2 compatible token login, get an access token for future requests
        """
        user = authenticate_user(form_data.username, form_data.password)

        if not user:
            raise HTTPException(status_code=400, detail="Incorrect email or password")
        elif is_user_active is not None and not is_user_active(user):
            raise HTTPException(status_code=400, detail="Inactive user")

        access_token_expires = timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)

        return {
            "access_token": create_access_token(
                data={"id": get_user_id(user), "rls": get_user_rolenames(user)},
                expires_delta=access_token_expires,
                secret_key=config.SECRET_KEY,
                algorithm=config.JWT_ENCODING_ALG,
            ),
            "token_type": "bearer",
        }


#  DI
def get_current_user(token: str = Security(OAuth2PasswordBearer(tokenUrl="/login"))):
    """[summary]
    Fetches current user from token. gets user id from token and fetches from DB
    """
    if LEGION_GLOBAL is None:
        raise Exception("You Must first create the Legion object via Legion(app, ...)")

    try:
        payload = jwt.decode(
            token,
            LEGION_GLOBAL.legion_config.SECRET_KEY,
            algorithms=LEGION_GLOBAL.legion_config.ACCEPTED_JWT_DECODE_ALGS,
        )
        token_data = TokenPayload(**payload)
    except PyJWTError:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="Could not validate credentials",
        )

    user = LEGION_GLOBAL.user_lookup_by_id(token_data.id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


class RolesAccepted:
    """
    Class that can be used within FastAPI dependency injection.
    Accepts any of the roles presented list of roles
    Example: Depends(RolesAccepted(["role_1", "role_2"]))

    """

    def __init__(self, roles: List[Role]):
        self.roles = roles

    def __call__(self, current_user: User = Security(get_current_user)):
        if LEGION_GLOBAL is None:
            raise Exception(
                "You Must first create the Legion object via Legion(app, ...)"
            )

        user_roles: Optional[List[str]] = LEGION_GLOBAL.get_user_rolenames(current_user)

        if user_roles is not None:
            for admitted_role in self.roles:
                if admitted_role in user_roles:
                    return True

        raise HTTPException(
            status_code=400, detail="The user doesn't have enough privilege"
        )


class RolesRequired:
    """
    Class that can be used within FastAPI dependency injection.
    Requires all roles to be present on user
    Example: Depends(RolesRequired(["role_1", "role_2"]))

    """

    def __init__(self, roles: List[Role]):
        self.roles = roles

    def __call__(self, current_user: User = Security(get_current_user)):
        if LEGION_GLOBAL is None:
            raise Exception(
                "You Must first create the Legion object via Legion(app, ...)"
            )

        user_roles: Optional[List[str]] = LEGION_GLOBAL.get_user_rolenames(current_user)

        if user_roles is not None and all(
            [required_role in user_roles for required_role in self.roles]
        ):
            return True

        raise HTTPException(
            status_code=400, detail="The user doesn't have enough privilege"
        )
