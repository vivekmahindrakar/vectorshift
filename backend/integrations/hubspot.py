# slack.py

import datetime
import json
import secrets
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import base64
import hashlib

import requests
from integrations.integration_item import IntegrationItem

from redis_client import add_key_value_redis, get_value_redis, delete_key_redis




CLIENT_ID = '2eb6cca7-65e0-4185-bca8-498d1c3c643a'
CLIENT_SECRET = '318562e6-b49c-41bc-a384-a1b3dd749784'
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
authorization_url = f'https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fintegrations%2Fhubspot%2Foauth2callback'

encoded_client_id_secret = base64.b64encode(f'{CLIENT_ID}:{CLIENT_SECRET}'.encode()).decode()
scope = 'crm.objects.companies.read crm.objects.companies.write'


async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')

    code_verifier = secrets.token_urlsafe(32)
    m = hashlib.sha256()
    m.update(code_verifier.encode('utf-8'))
    code_challenge = base64.urlsafe_b64encode(m.digest()).decode('utf-8').replace('=', '')

    auth_url = f'{authorization_url}&state={encoded_state}&scope={scope}'
    await asyncio.gather(
        add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600),
        add_key_value_redis(f'hubspot_verifier:{org_id}:{user_id}', code_verifier, expire=600),
    )

    return auth_url

async def oauth2callback_hubspot(request: Request):
    # Handle OAuth errors
    error = request.query_params.get("error")
    if error:
        raise HTTPException(status_code=400, detail=request.query_params.get("error_description"))

    # Extract and decode parameters
    code = request.query_params.get("code")
    encoded_state = request.query_params.get("state")
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode("utf-8"))

    user_id = state_data.get("user_id")
    org_id = state_data.get("org_id")
    original_state = state_data.get("state")

    # Retrieve state and code verifier from Redis
    state_key = f"hubspot_state:{org_id}:{user_id}"
    verifier_key = f"hubspot_verifier:{org_id}:{user_id}"
    saved_state, code_verifier = await asyncio.gather(
        get_value_redis(state_key),
        get_value_redis(verifier_key),
    )

    # Validate state
    if not saved_state or original_state != json.loads(saved_state).get("state"):
        raise HTTPException(status_code=400, detail="State does not match.")

    # Exchange the authorization code for an access token
    token_url = "https://api.hubapi.com/oauth/v1/token"
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    token_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }

    async with httpx.AsyncClient() as client:
        token_response, _, _ = await asyncio.gather(
            client.post(token_url, data=token_data , headers=token_headers),
            delete_key_redis(state_key),
            delete_key_redis(verifier_key),
        )

    # Save credentials in Redis
    credentials_key = f"hubspot_credentials:{org_id}:{user_id}"
    await add_key_value_redis(credentials_key, json.dumps(token_response.json()), expire=600)

    # Return a script to close the window
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_hubspot_credentials(user_id, org_id):
    key = f'hubspot_credentials:{org_id}:{user_id}'
    
    # Retrieve credentials from Redis
    credentials = await get_value_redis(key)
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    
    # Parse credentials and clean up the key in Redis
    await delete_key_redis(key)
    return json.loads(credentials)


def create_integration_item_metadata_object(
    response_json: str, item_type: str, parent_id=None, parent_name=None
) -> IntegrationItem:
    parent_id = None if parent_id is None else parent_id + '_Base'
    integration_item_metadata = IntegrationItem(
        id=response_json.get('id', None) + '_' + item_type,
        name=response_json.get('properties',None).get('name', None),
        domain=response_json.get('properties',None).get('domain', None),
        type=item_type,
        parent_id=parent_id,
        parent_path_or_name=parent_name,
    )

    return integration_item_metadata

def fetch_items(
    access_token: str, url: str, aggregated_response: list, offset=None
) -> dict:
    """Fetching the list of bases"""
    params = {'offset': offset} if offset is not None else {}
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        results = response.json().get('results', {})
        offset = response.json().get('limit', None)

        for item in results:
            aggregated_response.append(item)
            print(item)

        if offset is not None:
            fetch_items(access_token, url, aggregated_response, offset)
        else:
            return





async def get_items_hubspot(credentials):
    credentials = json.loads(credentials)
    url = 'https://api.hubapi.com/crm/v3/objects/companies'
    list_of_integration_item_metadata = []
    list_of_responses = []


    fetch_items(credentials.get('access_token'), url, list_of_responses)
    for response in list_of_responses:
        list_of_integration_item_metadata.append(
            create_integration_item_metadata_object(response, 'vectorshiftai')
        )
        
    print(f'list_of_integration_item_metadata: {list_of_integration_item_metadata}')
    return list_of_integration_item_metadata