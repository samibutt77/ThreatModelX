import jwt
import datetime
from flask import request
from functools import wraps
from models import User

SECRET = "CHANGE_THIS_TO_A_64BYTE_SECRET_KEY"


def create_jwt(user_id, role):
    payload = {
        "uid": user_id,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")


def jwt_required(role=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", None)

            if not auth or not auth.startswith("Bearer "):
                return {"error": "Missing Bearer token"}, 401

            token = auth.split(" ")[1]

            try:
                payload = jwt.decode(token, SECRET, algorithms=["HS256"])
            except jwt.ExpiredSignatureError:
                return {"error": "Token expired"}, 401
            except jwt.InvalidTokenError:
                return {"error": "Invalid token"}, 401

            # Role enforcement
            if role and payload.get("role") != role:
                return {"error": "Unauthorized role"}, 403

            request.jwt_user = payload   # attach user info to request

            return func(*args, **kwargs)

        return wrapper
    return decorator
