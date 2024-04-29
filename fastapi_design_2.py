from datetime import datetime
from typing import List
from fastapi import FastAPI, HTTPException, Depends
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware

# althrought it is used by fastapi internally anyway to convert data it can be useful to use explicitly in situations eg. wnt to ensure return/response can be encoded as JSON before sending to client / ensure JSON objects saved in DB.
from fastapi.security import (
    APIKeyCookie,
    APIKeyHeader,
    APIKeyQuery,
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
    HTTPDigest,
    OAuth2,
    OAuth2AuthorizationCodeBearer,
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    OAuth2PasswordRequestFormStrict,
    OpenIdConnect,
    SecurityScopes,
)
from pydantic import BaseModel

app2 = FastAPI()

# preflighted request with OPTIONS headers/method
app2.add_middleware(
    CORSMiddleware,
    allow_origins=["https://listofallowedsites.com"],
    # allow_origin_regex='https://.*\.com',
    allow_credentials=True,  # True == supports cookies for CO request (False default),
    allow_methods=["GET"],
    allow_headers=["Authorization"],
    expose_headers=[
        "X-Custom-Header"
    ],  # default == [] what response headers can be accessed by client,
    max_age=600,  # default value, max time in seconds that the client can cache the response
)


class Item(BaseModel):
    title: str
    timestamp: datetime
    description: List[str] | None = None


jsonable_encoder(
    obj=Item,
    include=None,
    exclude=None,
    by_alias=True,
    exclude_unset=False,
    exclude_defaults=False,
    exclude_none=False,
    custom_encoder=None,
    sqlalchemy_safe=True,
)
