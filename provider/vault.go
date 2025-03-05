package provider

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/vault/api"
	vault "github.com/hashicorp/vault/api"
)

type vaultKV struct {
	client    *vault.Client
	path      string
	managedBy string
	// TODO(antoine): look into adding the resource ID in the meta so  we cannot
	// overwrite the value within TF
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
	plaintext, ok := s.Data["plaintext"].(string)
	if !ok {
		return "", fmt.Errorf("the value of the decrypted secret is not a string")
	}

	return plaintext, nil
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
	ciphertext, ok := s.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("the value of the encrypted secret is not a string")
	}
	return ciphertext, nil
}

var vaultConfigSchema = schema.SingleNestedAttribute{
	Attributes: map[string]schema.Attribute{
		"endpoint":     schema.StringAttribute{Required: true},
		"ca_cert_file": schema.StringAttribute{Optional: true},
		"auth_login_cert": schema.SingleNestedAttribute{
			Attributes: map[string]schema.Attribute{
				"mount": schema.StringAttribute{
					Required:    true,
					Description: "The name of the authentication engine mount",
				},
				"name": schema.StringAttribute{
					Required:    true,
					Description: "Authenticate against only the named certificate role",
				},

				"cert_file": schema.StringAttribute{
					Required:    true,
					Description: "Path to a file on local disk that contains the PEM-encoded certificate to present to the server",
				},

				"key_file": schema.StringAttribute{
					Required:    true,
					Description: "Path to a file on local disk that contains the PEM-encoded private key for which the authentication certificate was issued",
				},
			},
			Optional: true,
		},
		"token": schema.StringAttribute{Optional: true},
	},
	Required: true,
}

type VaultConfigModel struct {
	Endpoint      string         `tfsdk:"endpoint"`
	CACertFile    *string        `tfsdk:"ca_cert_file"`
	Token         *string        `tfsdk:"token"`
	AuthLoginCert *AuthLoginCert `tfsdk:"auth_login_cert"`
}

func newClient(ctx context.Context, config VaultConfigModel) (*api.Client, error) {
	cfg := &vault.Config{Address: config.Endpoint}
	if config.CACertFile != nil {
		err := cfg.ConfigureTLS(&vault.TLSConfig{
			CACert: *config.CACertFile,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to configure vault client TLS %w", err)
		}
	}

	client, err := vault.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	if config.Token != nil {
		client.SetToken(*config.Token)
	}

	if config.AuthLoginCert != nil {
		_, err := client.Auth().Login(ctx, config.AuthLoginCert)
		if err != nil {
			return nil, fmt.Errorf("failed to login using the cert auth method: %w", err)
		}
	}

	return client, nil
}

type AuthLoginCert struct {
	Mount    string `tfsdk:"mount"`
	Name     string `tfsdk:"name"`
	CertFile string `tfsdk:"cert_file"`
	KeyFile  string `tfsdk:"key_file"`
}

// Login using the cert authentication engine.
func (l *AuthLoginCert) Login(ctx context.Context, client *api.Client) (*api.Secret, error) {
	c, err := client.Clone()
	if err != nil {
		return nil, err
	}

	config := client.CloneConfig()
	tlsConfig := config.TLSConfig()
	if tlsConfig == nil {
		return nil, fmt.Errorf("clone api.Config's TLSConfig is nil")
	}

	clientCert, err := tls.LoadX509KeyPair(l.CertFile, l.KeyFile)
	if err != nil {
		return nil, err
	}

	tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &clientCert, nil
	}

	switch t := config.HttpClient.Transport.(type) {
	case *http.Transport:
		t.TLSClientConfig = tlsConfig
	default:
		return nil, fmt.Errorf("HTTPClient has unsupported Transport type %T", t)
	}

	return c.Logical().Write(
		"auth/"+l.Mount+"/login",
		map[string]any{"name": l.Name},
	)
}
