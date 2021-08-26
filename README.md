# vault-secret-uploader

Component that uploads secrets to Vault and modifies its configuration so that only the user that uploaded the secret has access to it. It uses JWT authentication to identify the user.

## API endpoints

### /hpc \[POST\]

Endpoint to upload the ssh credentials to connect to an hpc. Payload:

```
{
"hpc": "<hpc address>",
"ssh_user": "<username>",
"ssh_password": "<password>",
"ssh_pkey": "<private key>"
}
```

"hpc" and "ssh_user" fields are mandatory.
One of "ssh_password" or "ssh_pkey" must be included (it can also be both).

Example:

```
curl 192.168.3.74:8202/hpc -X POST -H 'Content-Type: application/json' -H 'authorization: Bearer eyJhbGciOiJSUzI1NiI...AmqlQ' -d '{"hpc": "ft2.cesga.es", "ssh_user": "jesus", "ssh_password": "pass123", "ssh_pkey": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAtoVZsYJNJOkSF...onQ==\n-----END RSA PRIVATE KEY-----"}'
```

It's important that the private key has that exact format (starts with -----BEGIN RSA PRIVATE KEY-----, then \n, then the key without line breaks, then \n, then -----END RSA PRIVATE KEY-----).

## Deployment

A docker image is provided to launch this conmponent in a container. Image can be found in [sodaliteh2020/vault-secret-uploader](https://hub.docker.com/r/sodaliteh2020/vault-secret-uploader/tags?page=1&ordering=last_updated)
Environment variables needed to configure the container:

- VAULT_SECRET_UPLOADER_PORT: Port on which to serve the API.
- OIDC_CLIENT_ID: Client name of the OIDC service.
- OIDC_CLIENT_SECRET: Client secret of the OIDC service.
- OIDC_INTROSPECTION_ENDPOINT: Endpoint of the service used to validate JWTs.
- VAULT_ADDRESS: Address of the Vault instance.
- VAULT_PORT: Port used in the Vault instance.
- VAULT_ADMIN_TOKEN: Vault token that has at least permissions to create secrets under /hpc, create roles and create policies.