terraform {
  required_version = ">= 1.6.3"

  required_providers {
    vault-secrets-as-code = {
      source  = "7fELF/vault-secrets-as-code"
      version = "0.0.1"
    }
  }
}
