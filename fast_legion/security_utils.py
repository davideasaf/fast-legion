"Legion Security Utils"
from datetime import datetime, timedelta
from uuid import uuid4

import jwt


def create_access_token(
    *,
    data: dict,
    expires_delta: timedelta = timedelta(minutes=15),
    secret_key: str,
    algorithm: str,
    jwt_subject="access",
):
    """
    Creates a JWT access token. This currently matches base flask-praetorian defaults
    """
    to_encode = data.copy()

    expire = datetime.utcnow() + expires_delta

    refresh_exp = datetime.utcnow() + timedelta(weeks=4)
    to_encode.update(
        {
            "iat": datetime.utcnow(),
            "exp": expire,
            "sub": jwt_subject,
            "jti": str(uuid4()),
            # "rf_exp": int(refresh_exp.timestamp()),
        }
    )
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
    return encoded_jwt
