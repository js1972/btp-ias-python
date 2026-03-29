import requests

# IAS OAuth2 Config
TOKEN_URL = "https://ias-tenant.accounts.cloud.sap/oauth2/token"
CLIENT_ID = "6b662d...[client_id]...e9c7e9"
CLIENT_SECRET = "PLSD....[client_secret]...sdfsdfs"
API_URL = "https://app-name.cfapps.sap.hana.ondemand.com"

# 1. Get Token from IAS
resp = requests.post(
    TOKEN_URL,
    data={
        "grant_type": "client_credentials"
    },
    auth=(CLIENT_ID, CLIENT_SECRET)
)
print(resp.content)
token = resp.json()["access_token"]
print(f"✓ Token: {token[:20]}...")

# 2. API Request with Token
response = requests.get(
    API_URL + "/secure",
    headers={"Authorization": f"Bearer {token}"}
)
print(f"✓ With Token - Status: {response.status_code}")
print(f"✓ Response: {response.json()}")

# 3. API Request without Token (should fail with 401)
response_no_token = requests.get(API_URL + "/secure")
print(f"✗ Without Token - Status: {response_no_token.status_code}")
print(f"✗ Response: {response_no_token.json()}")