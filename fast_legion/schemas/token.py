"Token Schemas"
from pydantic import BaseModel


class Token(BaseModel):
    """[summary]
    Token Schema
    """

    access_token: str
    token_type: str


class TokenPayload(BaseModel):
    """[summary]
    Token Payload Schema
    """

    id: int
