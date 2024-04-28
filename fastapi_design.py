import random
import string
import threading
import time
from fastapi import FastAPI, HTTPException, Depends

# extend openapi schema
from fastapi.openapi.utils import get_openapi
import uvicorn

# rate limiter
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter

# JWT, AUTH
import jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext

app = FastAPI()


# JWT config. Would be used in .env, not hardcoded, hidden/not accessible
# Secret key for signing JWT tokens. including secret key rotation
SECRET_KEY = os.environ.get("SECRET_KEY", None)
# If SECRET_KEY is not provided as an environment variable, generate a random one
if SECRET_KEY is None:
    SECRET_KEY = "".join(
        random.SystemRandom().choice(string.ascii_letters + string.digits)
        for _ in range(64)
    )

# Algorithm used for JWT token encoding
ALGORITHM = "HS256"

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 password bearer flow for token retrieval
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Initialize FastAPILimiter
limiter = FastAPILimiter(app)


@limiter.limit("5/minute")

# Add SSL certificate and Key files
@app.get("/")
async def root():
    return {"message": "Added digitalcerts by specifying SSL certificate and Key files"}


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        ssl_keyfile="path/to/key.pem",
        ssl_certfile="path/to/cert.pem",
    )


# Extend openapi schema
# from fastapi.openapi.utils import get_openapi
@app.get("/items/")
async def read_items():
    return [{"name": "Foo"}]


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Custom title",
        version="2.5.0",
        summary="This is a very custom OpenAPI schema",
        description="Here's a longer description of the custom **OpenAPI** schema",
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema


@app.get("/items/")
async def read_items_rate_limiter():
    return {"message": "This endpoint is rate-limited."}


# ------------JWT related code------------------------
# 1. Implement an authentication service responsible for authenticating users and generating JWT tokens
# Authentication function
def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or not pwd_context.verify(password, user["password"]):
        return False
    return user


# Token generation function
def create_access_token(data: dict):
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Dependency for extracting and verifying JWT token
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )
        token_data = {"username": username}
    except jwt.JWTError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials"
        )
    return token_data


# 2. Implement an endpoint for generating JWT tokens upon successful authentication
app = FastAPI()


@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token_data = {"sub": user["username"]}
    access_token = create_access_token(token_data)
    return {"access_token": access_token, "token_type": "bearer"}


# 3. Implement an endpoint for generating JWT tokens upon successful authentication
@app.get("/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    return {
        "message": f"Beware, {current_user['username']}. This is a protected route."
    }


# Secret key rotation functionality
def rotate_secret_key():
    """Rotate the secret key."""
    global SECRET_KEY
    new_secret_key = generate_secret_key()
    SECRET_KEY = new_secret_key
    print("Secret key rotated.")


def schedule_key_rotation(interval_seconds):
    """Schedule secret key rotation at regular intervals."""
    while True:
        rotate_secret_key()
        time.sleep(interval_seconds)


def generate_secret_key(length=32):
    """Generate a random string of letters and digits for the secret key."""
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


if __name__ == "__main__":
    # Start key rotation in a separate thread
    rotation_interval_seconds = 3600  # Rotate key every hour (adjust as needed)
    rotation_thread = threading.Thread(
        target=schedule_key_rotation, args=(rotation_interval_seconds,)
    )
    rotation_thread.daemon = True
    rotation_thread.start()


# --------JWT END------------

app.openapi = custom_openapi
