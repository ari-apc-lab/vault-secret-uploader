from base64 import b64encode
from os import getenv
from flask import Flask, request
from requests import post, Session, adapters, get, delete
from requests import request as req_request
import json
import re

app = Flask(__name__)
dashboard_urls = {}
dashboard_uids = {}
dashboard_ids = {}
user_ids = {}
oidc_client_id = getenv("OIDC_CLIENT_ID", "sodalite-ide")
oidc_client_secret = getenv("OIDC_CLIENT_SECRET", "")
oidc_introspection_endpoint = getenv("OIDC_INTROSPECTION_ENDPOINT", "")
vault_endpoint = getenv("VAULT_ADDRESS", "") + ":" + getenv("VAULT_PORT", "8200")
vault_admin_token = getenv("VAULT_ADMIN_TOKEN", "")

session = Session()
adapter = adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
for protocol in ['http:', 'https:']:
    session.mount(protocol, adapter)


@app.route('/croupier', methods=['POST'])
def upload_croupier_secret():

    json_data = request.json
    if "host" in json_data:
        host = json_data["host"]
    else:
        return "Request must include host or service (\"host\")\n", 403

    if not _validate_host(host):
        return "Not a valid host", 403

    json_secret = json_data

    secret_endpoint = "http://" + vault_endpoint + "/v1/croupier/{0}/" + host

    return _upload_secret(request, secret_endpoint, json_secret, "croupier")


@app.route('/ssh', methods=['POST'])
def upload_ssh_secret():

    json_data = request.json
    if "ssh_host" in json_data:
        ssh_host = json_data["ssh_host"]
    else:
        return "Request must include SSH host (\"ssh_host\")\n", 403

    if not _validate_host(ssh_host):
        return "Not a valid host", 403

    if "ssh_user" in json_data:
        ssh_user = json_data["ssh_user"]
    else:
        return "Request must include SSH user (\"ssh_user\")\n", 403

    ssh_pw = json_data["ssh_password"] if "ssh_password" in json_data else ""
    ssh_pkey = json_data["ssh_pkey"] if "ssh_pkey" in json_data else ""

    if not ssh_pw and not ssh_pkey:
        return "Request must include either SSH password (\"ssh_pw\") or SSH private key (\"ssh_pkey\")\n", 403

    json_secret = {"ssh_user": ssh_user, "ssh_host": ssh_host}

    if ssh_pw:
        json_secret["ssh_password"] = ssh_pw
    if ssh_pkey:
        json_secret["ssh_pkey"] = ssh_pkey

    secret_endpoint = "http://" + vault_endpoint + "/v1/ssh/{0}/" + ssh_host

    return _upload_secret(request, secret_endpoint, json_secret, "ssh")


@app.route('/keycloak', methods=['POST'])
def upload_keycloak_secret():

    json_data = request.json
    if "password" in json_data:
        password = json_data["password"]
    else:
        return "Request must include keycloak password (\"password\")\n", 403

    json_secret = {"password": password}
    secret_endpoint = "http://" + vault_endpoint + "/v1/keycloak/{0}"

    return _upload_secret(request, secret_endpoint, json_secret, "keycloak")


@app.route('/ssh', methods=['GET'])
def list_ssh_secrets():
    try:
        jwt = _get_token(request)
        user_info = _token_info(jwt)
    except Exception as e:
        return str(e), 500
    if not user_info:
        return "Unauthorized access\n", 401

    username = user_info["preferred_username"]

    vault_user_token = _get_vault_token(jwt, username)

    if vault_user_token == "":
        return ({}, 200)

    secret_endpoint = "http://" + vault_endpoint + "/v1/ssh/" + username
    auth_header = {"x-vault-token": vault_user_token}

    vault_secret_response = req_request('LIST', secret_endpoint, headers=auth_header)
    if not vault_secret_response.ok:
        return ("There was a problem listing the secrets from vault:\n" + str(vault_secret_response.content) + "\n",
                vault_secret_response.status_code)

    list_secrets = {"list": vault_secret_response.json()["data"]["keys"]}

    return list_secrets, 200


@app.route('/ssh/<ssh_host>', methods=['GET'])
def get_ssh_secret(ssh_host):
    secret_endpoint = "http://" + vault_endpoint + "/v1/ssh/{0}/" + ssh_host
    return _get_secret(request, secret_endpoint)


@app.route('/keycloak', methods=['GET'])
def get_keycloak_secret():
    secret_endpoint = "http://" + vault_endpoint + "/v1/keycloak/{0}"
    return _get_secret(request, secret_endpoint)


@app.route('/ssh/<ssh_host>', methods=['DELETE'])
def delete_ssh_secret(ssh_host):
    if not _validate_host(ssh_host):
        return "Not a valid host", 403
    secret_endpoint = "http://" + vault_endpoint + "/v1/ssh/{0}/" + ssh_host
    return _delete_secret(request, secret_endpoint)


@app.route('/keycloak', methods=['DELETE'])
def delete_keycloak_secret():
    secret_endpoint = "http://" + vault_endpoint + "/v1/keycloak/{0}"
    return _delete_secret(request, secret_endpoint)


def _upload_secret(request, endpoint, json_secret, secret_type):
    try:
        user_info = _token_info(_get_token(request))
    except Exception as e:
        return str(e), 500
    if not user_info:
        return "Unauthorized access\n", 401

    username = user_info["preferred_username"]
    auth_header = {"x-vault-token": vault_admin_token}
    json_policy = {
        "policy": "path \"/" + secret_type + "/" + username + "/*\"\n"
                  "{\n"
                  "  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n"
                  "}\n"
                  "path \"/" + secret_type + "/" + username + "\"\n"
                  "{\n"
                  "  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n"
                  "}\n"
    }

    role_endpoint = "http://" + vault_endpoint + "/v1/auth/jwt/role/" + username

    role_policies = _get_role_policies(role_endpoint)
    
    if isinstance(role_policies, list):
        role_policies.append(secret_type + "-" + username)
    else:
        return ("There was a problem retrieving roles for the user")

    json_role = {
        "policies": role_policies,
        "role_type": "jwt",
        "bound_audiences": "account",
        "user_claim": "email",
        "groups_claim": "",
        "bound_claims": {
            "preferred_username": username
        }
    }

    policy_endpoint = "http://" + vault_endpoint + "/v1/sys/policy/" + secret_type + "-" + username

    secret_endpoint = endpoint.format(username)

    policy_response = post(policy_endpoint, data=json.dumps(json_policy), headers=auth_header)

    if not policy_response.ok:
        return ("There was a problem creating the policy:\n" + str(policy_response.content) + "\n",
                policy_response.status_code)

    role_response = post(role_endpoint, data=json.dumps(json_role), headers=auth_header)

    if not role_response.ok:
        return ("There was a problem binding the keycloak user to the policy:\n" + str(role_response.content) + "\n",
                role_response.status_code)

    secret_response = post(secret_endpoint, data=json.dumps(json_secret), headers=auth_header)

    if not secret_response.ok:
        return ("There was a problem creating the secret:\n" + str(secret_response.content) + "\n",
                secret_response.status_code)

    return "Secret uploaded correctly\n", 200


def _get_role_policies(endpoint):
    auth_header = {"x-vault-token": vault_admin_token}
    vault_response = get(endpoint, headers=auth_header)
    if vault_response.status_code == 404:
        return []
    elif vault_response.ok:
        response_json = vault_response.json()
        if "policies" in response_json["data"]:
            return response_json["data"]["policies"]
        else:
            return []
    else:
        return None


def _get_secret(request, endpoint):
    try:
        jwt = _get_token(request)
        user_info = _token_info(jwt)
    except Exception as e:
        return str(e), 500
    if not user_info:
        return "Unauthorized access\n", 401

    username = user_info["preferred_username"]

    vault_user_token = _get_vault_token(jwt, username)

    if vault_user_token == "":
        return ({}, 200)

    secret_endpoint = endpoint.format(username)
    auth_header = {"x-vault-token": vault_user_token}

    vault_secret_response = get(secret_endpoint, headers=auth_header)
    if not vault_secret_response.ok:
        return ("There was a problem getting the secret from vault:\n" + str(vault_secret_response.content) + "\n",
                vault_secret_response.status_code)

    json_data = vault_secret_response.json()["data"]

    return json_data, 200


def _delete_secret(request, endpoint):

    try:
        jwt = _get_token(request)
        user_info = _token_info(jwt)
    except Exception as e:
        return str(e), 500
    if not user_info:
        return "Unauthorized access\n", 401

    username = user_info["preferred_username"]

    vault_user_token = _get_vault_token(jwt, username)

    if vault_user_token == "":
        return ("No secrets found for the user", 404)

    secret_endpoint = endpoint.format(username)
    auth_header = {"x-vault-token": vault_user_token}

    vault_secret_response = delete(secret_endpoint, headers=auth_header)
    if not vault_secret_response.ok:
        return ("There was a problem deleting the secret from vault:\n" + str(vault_secret_response.content) + "\n",
                vault_secret_response.status_code)

    return "Secret deleted successfully", 200


def _token_info(access_token) -> dict:

    req = {'token': access_token}
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    if not oidc_introspection_endpoint:
        raise Exception("No oidc_introspection_endpoint set on the server\n")

    basic_auth_string = '{0}:{1}'.format(oidc_client_id, oidc_client_secret)
    basic_auth_bytes = bytearray(basic_auth_string, 'utf-8')
    headers['Authorization'] = 'Basic {0}'.format(b64encode(basic_auth_bytes).decode('utf-8'))

    token_response = post(oidc_introspection_endpoint, data=req, headers=headers)
    if not token_response.ok:
        raise Exception("There was a problem trying to authenticate with keycloak:\n"
                        " HTTP code: " + str(token_response.status_code) + "\n"
                        " Content:" + str(token_response.content) + "\n")

    json = token_response.json()
    if "active" in json and json["active"] is False:
        return {}
    return json


def _get_token(r):
    auth_header = r.environ["HTTP_AUTHORIZATION"].split()
    if auth_header[0] == "Bearer":
        return auth_header[1]
    return ""


def _get_vault_token(jwt, username):
    url = "http://" + vault_endpoint + "/v1/auth/jwt/login"
    payload = {
        "jwt": jwt,
        "role": username
    }
    response = post(url, json=payload)
    if response.ok:
        json = response.json()
        user_token = json["auth"]["client_token"]
        return user_token
    else:
        return ""


def _validate_host(host):
    pattern = re.compile("^([a-z0-9A-Z_-]+\.)*[a-zA-Z0-9_]+$")
    return pattern.match(host)