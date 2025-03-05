provider "vault-secrets-as-code" {
  // vault server -dev -dev-root-token-id=blipblop
  transit_vault_config = {
    endpoint = "http://127.0.0.1:8200"
    token    = "blipblop"
  }

  // can be the same or a different vault server
  kv_vault_config = {
    endpoint = "http://127.0.0.1:8200"
    token    = "blipblop"
  }

  transit_path = "transit/"
  transit_key  = "my-key"
  kv_path      = "secret/"

  managed_by = "terraform-vault-secrets-as-code"
}

resource "vault-secrets-as-code_secret" "mysupersecret" {
  path = "my/super/secret"
  encrypted_secrets = {
    // vault write transit/encrypt/my-key plaintext=$(echo "mario" | base64)
    itsame = "vault:v1:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  }
}
