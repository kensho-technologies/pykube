"""
Open ID Connect (OIDC) related code.
"""

import base64
import json
import requests
import six
import time


# If our token is about to expire we should refresh in anticipation
EXPIRY_BUFFER_SECONDS = 10


def _pad_b64(b64):
    """Fix padding for base64 value if necessary"""
    pad_len = len(b64) % 4
    if pad_len != 0:
        missing_padding = (4 - pad_len)
        b64 += '=' * missing_padding
    return b64


def _id_token_expired(id_token):
    """Is this id token expired?"""
    parts = id_token.split('.')
    if len(parts) != 3:
        raise RuntimeError('ID Token is not valid')
    payload_b64 = _pad_b64(parts[1])
    if isinstance(payload_b64, six.binary_type):
        payload_b64 = six.text_type(payload_b64, encoding='utf-8')
    payload = base64.b64decode(payload_b64)
    payload_json = json.loads(payload)
    expiry = payload_json['exp']
    now = int(time.time())
    return (now + EXPIRY_BUFFER_SECONDS) > expiry


def _token_endpoint(auth_config):
    """Get the token endpoint from the well known config"""
    idp_issuer_url = auth_config.get('idp-issuer-url')

    if not idp_issuer_url:
        raise RuntimeError('idp-issuer-url not found in config')

    discovery_endpoint = idp_issuer_url + '/.well-known/openid-configuration'
    r = requests.get(discovery_endpoint)
    r.raise_for_status()
    discovery_json = r.json()
    return discovery_json['token_endpoint']


def _refresh_id_token(auth_config):
    """Generate a new id token from the refresh token"""
    refresh_token = auth_config.get('refresh-token')

    if not refresh_token:
        raise RuntimeError('id-token missing or expired and refresh-token is missing')

    client_id = auth_config.get('client-id')
    if not client_id:
        raise RuntimeError('client-id not found in auth config')

    client_secret = auth_config.get('client-secret')
    if not client_secret:
        raise RuntimeError('client-secret not found in auth config')

    token_endpoint = _token_endpoint(auth_config)
    data = {
        'grant_type': 'refresh_token',
        'client_id': client_id,
        'client_secret': client_secret,
        'refresh_token': refresh_token,
    }
    r = requests.post(token_endpoint, data=data)
    r.raise_for_status()
    return r.json()['id_token']


def _persist_credentials(config, id_token):
    user_name = config.contexts[config.current_context]['user']
    user = [u['user'] for u in config.doc['users'] if u['name'] == user_name][0]
    user['auth-provider']['config']['id-token'] = id_token
    config.persist_doc()
    config.reload()


def _id_token(auth_provider):
    """Return the configured id token if it is not expired, otherwise refresh it"""
    auth_config = auth_provider.get('config')

    if not auth_config:
        raise RuntimeError('auth-provider config not found')

    id_token = auth_config.get('id-token')
    should_persist = False
    if not id_token or _id_token_expired(id_token):
        id_token = _refresh_id_token(auth_config)
        auth_config['id-token'] = id_token
        should_persist = True
    return id_token, should_persist


def handle_oidc(request, config, auth_provider):
    """Handle authentication via Open ID Connect"""
    id_token, should_persist = _id_token(auth_provider)

    if should_persist:
        _persist_credentials(config, id_token)

    request.headers['Authorization'] = 'Bearer {}'.format(id_token)
