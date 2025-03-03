package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/vault/api"
	vault "github.com/hashicorp/vault/api"
)

type vaultKV struct {
	client    *vault.Client
	path      string
	managedBy string
}

func (v vaultKV) Destroy(ctx context.Context, k string) error {
	kv := v.client.KVv2(v.path)

	meta, err := kv.GetMetadata(ctx, k)
	if err != nil {
		return err
	}

	if managedBy, ok := meta.CustomMetadata["managed_by"]; !ok {
		return fmt.Errorf("%q is not managed by this Terraform configuration", k)
	} else if managedBy != v.managedBy {
		return fmt.Errorf("%q is not managed by this Terraform configuration (managedBy: %q)", k, managedBy)
	}

	versions := []int{}
	for _, v := range meta.Versions {
		versions = append(versions, v.Version)
	}

	if err := kv.DeleteMetadata(ctx, k); err != nil {
		return err
	}

	return nil
}

func (v vaultKV) OverwriteManagedbyMeta(ctx context.Context, k string) error {
	kv := v.client.KVv2(v.path)
	return kv.PutMetadata(ctx, k, api.KVMetadataPutInput{
		CustomMetadata: map[string]any{"managed_by": v.managedBy},
	})
}

func (v vaultKV) Put(ctx context.Context, k string, value map[string]any) error {
	kv := v.client.KVv2(v.path)

	meta, err := kv.GetMetadata(ctx, k)
	if err == nil {
		managedBy, ok := meta.CustomMetadata["managed_by"]
		if !ok {
			return fmt.Errorf("%q is not managed by this Terraform configuration", k)
		} else if managedBy != v.managedBy {
			return fmt.Errorf("%q is not managed by this Terraform configuration (managedBy: %q)", k, managedBy)
		}
	} else if !errors.Is(err, api.ErrSecretNotFound) {
		return err
	}

	err = v.OverwriteManagedbyMeta(ctx, k)
	if err != nil {
		return err
	}

	_, err = kv.Put(ctx, k, value)
	if err != nil {
		return err
	}

	return nil
}

type vaultTransit struct {
	client *vault.Client
	path   string
	key    string
}

func (v vaultTransit) Decrypt(ctx context.Context, ciphertext string) (string, error) {
	s, err := v.client.Logical().
		WriteWithContext(
			ctx,
			v.path+"decrypt/"+v.key,
			map[string]any{"ciphertext": ciphertext},
		)
	if err != nil {
		return "", err
	}
	return s.Data["plaintext"].(string), nil
}

func (v vaultTransit) Encrypt(ctx context.Context, plaintext string) (string, error) {
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
	s, err := v.client.Logical().
		WriteWithContext(
			ctx,
			v.path+"encrypt/"+v.key,
			map[string]any{"plaintext": encoded},
		)
	if err != nil {
		return "", err
	}
	return s.Data["ciphertext"].(string), nil
}

type VaultConfigModel struct {
	Endpoint types.String `tfsdk:"endpoint"`

	// CA   types.String `tfsdk:"ca"`
	// Cert types.String `tfsdk:"cert"`
	// Key  types.String `tfsdk:"key"`

	Token types.String `tfsdk:"token"`
}

func newClient(config VaultConfigModel) (*api.Client, error) {
	client, err := vault.NewClient(&vault.Config{
		Address:    config.Endpoint.ValueString(),
		HttpClient: &http.Client{},
	})
	if err != nil {
		return nil, err
	}

	client.SetToken(config.Token.ValueString())
	return client, nil
}
