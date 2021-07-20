from base64 import b64encode
from os import getenv
from flask import Flask, request
from requests import post, Session, adapters
import json

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


@app.route('/hpc', methods=['POST'])
def upload_hpc_secret():
    try:
        user_info = _token_info(_get_token(request))
    except Exception as e:
        return str(e), 500
    if not user_info:
        return "Unauthorized access\n", 401

    username = user_info["preferred_username"]
    json_data = request.json

    if "hpc" in json_data:
        hpc_name = json_data["hpc"]
    else:
        return "Request must include HPC name (\"hpc\")\n", 403

    if "ssh_user" in json_data:
        ssh_user = json_data["ssh_user"]
    else:
        return "Request must include SSH user (\"ssh_user\")\n", 403

    ssh_pw = json_data["ssh_password"] if "ssh_password" in json_data else ""
    ssh_pkey = json_data["ssh_pkey"] if "ssh_pkey" in json_data else ""

    if not ssh_pw and not ssh_pkey:
        return "Request must include either SSH password (\"ssh_pw\") or SSH private key (\"ssh_pkey\")\n", 403

    auth_header = {"x-vault-token": vault_admin_token}
    json_policy = {
        "policy": "path \"hpc/" + username + "/*\"\n"
                  "{\n"
                  "  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n"
                  "}\n"
                  "path \"hpc/*\"\n"
                  "{\n"
                  "  capabilities = [\"list\"]\n"
                  "}"
    }

    json_role = {
        "policies": ["hpc-" + username],
        "role_type": "jwt",
        "bound_audiences": "account",
        "user_claim": "email",
        "groups_claim": "",
        "bound_claims": {
            "preferred_username": username
        }
    }

    json_secret = {"user": ssh_user}

    if ssh_pw:
        json_secret["password"] = ssh_pw
    else:
        json_secret["private_key"] = ssh_pkey

    policy_endpoint = "http://" + vault_endpoint + "/v1/sys/policy/hpc-" + username
    role_endpoint = "http://" + vault_endpoint + "/v1/auth/jwt/role/" + username
    secret_endpoint = "http://" + vault_endpoint + "/v1/hpc/" + username + "/" + hpc_name

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


def _token_info(access_token) -> dict:

    req = {'token': access_token}
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    if not oidc_introspection_endpoint:
        raise Exception("No oidc_introspection_endpoint set on the server\n")

    basic_auth_string = '{0}:{1}'.format(oidc_client_id, oidc_client_secret)
    basic_auth_bytes = bytearray(basic_auth_string, 'utf-8')
    headers['Authorization'] = 'Basic {0}'.format(b64encode(basic_auth_bytes).decode('utf-8'))

    token_response = post(oidc_introspection_endpoint, data=req, headers=headers)
    if token_response.status_code != 200:
        raise Exception("There was a problem trying to authenticate with keycloak:\n"
                        " HTTP code: " + str(token_response.status_code) + "\n"
                        " Content:" + str(token_response.content) + "\n")
    if not token_response.ok:
        return {}
    json = token_response.json()
    if "active" in json and json["active"] is False:
        return {}
    return json


def _get_token(r):
    auth_header = r.environ["HTTP_AUTHORIZATION"].split()
    if auth_header[0] == "Bearer":
        return auth_header[1]
    return ""
