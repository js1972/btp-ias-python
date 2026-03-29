# Using IAS to Secure Python APIs on Cloud Foundry

__NOTE: This repo is copied and adopted from the awesome work here: https://github.com/fyx99/btp-ias-python__

In this blog post, I'll demonstrate how to use SAP Cloud Identity Services - Identity Authentication Service (IAS) to implement authentication for a Python API. This approach is particularly useful when building AI Agents or MCP servers that need protection from unauthorized access.

## Scenario

Given an HTTP-based API, we want to implement an authentication check. This might be, for example, a backend service consumed by another service. In this case, the OAuth Client Credentials flow is the industry standard to secure that access. This flow deals with clients that have access to certain APIs within specific scopes.

For my use case, I'm currently working on securing an MCP server (detailed blog posts will follow on that topic). The expected result is that my API sits behind an authentication check, where only clients with proper client credentials and granular permissions can access it. IAS serves as the authorization authority and provides the infrastructure and UI to handle the creation of client credentials and scoping.

## Prerequisites

To follow along with this blog post, you will need:
- Admin access to an IAS tenant (you can always create one with the additional tenant plan on BTP or reuse an existing one)
- Proper privileges to deploy an app to Cloud Foundry

## Creating an Application in IAS

The first step to enable such a setup is to create an application in IAS. This can be done by logging in to the admin panel of your IAS tenant.

Once logged in, use the **Create** button to start the application creation process.

![IAS App Create](images/ias%20app%20create.png)

You'll have several options to choose from. Select **SAP BTP Solution** as the type (there are also some other special types available). For the protocol, choose **OIDC** and you don't need to select any parent application.

Once the application is created, we can specify the **Provided APIs** - these work similar to scopes. Here we can define different APIs we want to expose. For example, I create:
- One scope for **Read Access**: `api_read_access`
- One scope for **Write Access**: `api_write_access`

![IAS Add APIs](images/ias%20add%20apis.png)

Now we can go ahead and create individual access keys with selected APIs. Let's start with a full access key. To do this, create a new secret in the **Secrets** section of the **Client Authentication** menu of your application. Select the **API Access** level - in which I only opt for **Application** - and then select the **API Permission Groups**. Here we see the different provided APIs from earlier. For full access, I select both APIs.

![IAS Add Secret](images/ias%20add%20secret.png)

Later on, for demonstration purposes, I also create one key with only the read access permission.

![IAS Scoped Keys](images/ias%20scoped%20keys.png)

![IAS Secret Show](images/ias%20secret%20show.png)

This completes the setup on the IAS side. To summarize: We have an application with a client ID and have created several scoped secrets. Now we can go ahead and implement the authentication check on the Python side.

## Implementing the Authentication Check

Here's the Python implementation using FastAPI:

```python
import os
import requests
import jwt
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Config - Load from environment variables
# Note: the issuer value must be exact and can be found at https://<ias tenant>/.well-known/openid-configuration
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


```

## Understanding the Code

Let's examine the code sample in detail:

We start with a basic FastAPI server that has a `/secure` endpoint that needs to be protected. This is accomplished by adding a middleware that checks the Authorization header of every request. Specifically, we expect a Bearer token, which is then verified.

The verification process is particularly interesting. First, we need to retrieve the public keys from the IAS tenant we're using. JWKS (JSON Web Key Set) is a set of keys containing the public keys used to verify JSON Web Tokens (JWT) issued by the authorization server.

We use the PyJWT library to decode the token and verify its signature with the public key. This is a cryptographic process that ensures the token is indeed valid and was issued by IAS. Once the content is verified, we can implement the specific checks we need.

In this example, we check for the scope - specifically whether the service key actually has the `api_read_access` permission group.

On the backend side, we specify the **issuer** and the **audience** for our authentication check:
- The **issuer** is the token issuer we want to trust
- The **audience** refers to the application (its client ID)

These two variables are hard-coded for this example, but in practice, you would want to pass them via an environment variable or a user-provided service to your app instance to ensure the code is independent of the current stage.

## Deploying to Cloud Foundry

To make this example deployable on Cloud Foundry, we add a manifest like this:

```yaml
---
applications:
- name: btp-ias-python
  memory: 1024M
  disk_quota: 4024M
  buildpack: python_buildpack
  command: python btp_ias_auth_example.py
```

With this manifest in place, we can run `cf push` and see the result in action.

Set the required env vars for IAS with:
```
cf set-env btp-ias-python IAS_ISSUER "<issuer_url>"
cf set-env btp-ias-python IAS_AUDIENCE "<client_id>"
```

The issuer value must be exact and can be found at https://<ias tenant>/.well-known/openid-configuration

## Testing the Secured API

Now let's look at how to make requests from the client side:

```bash
# 1. Get Token
curl -X POST "https://ias-tenant.accounts.cloud.sap/oauth2/token" \
  -u "1d3656f2-xxxx-xxxx-xxxx-7c69088b43b7:s?_Hexxxxxxxxxxxxxxxxc=1_" \
  -d "grant_type=client_credentials"

Result:

200: {"access_token":"eyJqa3UiOiJodHRwczovL2FzcW8wb2F6Mi5hY2NvdW5mZGFlOWM3......


# 2. Request with Token 
curl -X GET "https://api-url.eu12.cfapps.ondemand.com/secure" \
  -H "Authorization: Bearer TOKEN_HERE"

Result:

200: {'message': 'authorized'}

# 3. Request without Token (expect 401)
curl -X GET "https://api-url.eu12.cfapps.ondemand.com/secure"

Result:

401: {'detail': 'Missing token'}
```

## How It Works

On the client side, we follow the standard OAuth2 token retrieval flow: we provide our client ID and client secret (from one of the keys we created earlier) to get an access token. Then we can pass this token in the Authorization header and make the request.

And voilà: we get the expected response!

## Conclusion

In this blog post, we've seen how to:
1. Configure an application in IAS with scoped API permissions
2. Create client credentials with different permission levels
3. Implement JWT token verification in a Python FastAPI application
4. Deploy the secured API to Cloud Foundry
5. Test the authentication flow with different scenarios

This pattern provides a robust and scalable way to secure your Python APIs using SAP's Identity Authentication Service, with fine-grained control over which clients can access which endpoints.

I hope you enjoyed this blog post and found it helpful for your own projects! 
