import os
import requests
import jwt
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Config - Load from environment variables
ISSUER = os.environ.get("IAS_ISSUER", "https://your-tenant.accounts.ondemand.com")
JWKS_URL = f"{ISSUER}/oauth2/certs"
AUDIENCE = os.environ.get("IAS_AUDIENCE", "your-client-id-here")

def get_public_key(token: str):
    """Holt JWKS und findet den passenden Public Key"""
    kid = jwt.get_unverified_header(token)["kid"]
    jwks = requests.get(JWKS_URL).json()

    for key in jwks["keys"]:
        if key["kid"] == kid:
            return jwt.algorithms.RSAAlgorithm.from_jwk(key)

    raise Exception("No matching key found")


def verify_token(token: str):
    """Validiert JWT Token"""
    public_key = get_public_key(token)
    payload = jwt.decode(token, public_key, algorithms=["RS256"],
                        audience=AUDIENCE, issuer=ISSUER)

    if "api_read_access" not in payload.get("ias_apis", []):
        raise Exception("Missing required ias_apis scope")

    return payload

# FastAPI App
app = FastAPI()

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Missing token"})

    token = auth_header.split(" ")[1]

    try:
        payload = verify_token(token)
        request.state.user = payload
    except Exception as e:
        return JSONResponse(status_code=401, content={"detail": str(e)})

    return await call_next(request)

@app.get("/secure")
def secure(request: Request):
    return {
        "message": "authorized"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

