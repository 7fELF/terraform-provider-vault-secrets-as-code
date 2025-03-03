package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// Provider defines the providervimplemengation.
type Provider struct {
	version string
}

// ProviderModel describes the provider data model.
type ProviderModel struct {
	TransitVaultConfig types.Object `tfsdk:"transit_vault_config"`
	KVVaultConfig      types.Object `tfsdk:"kv_vault_config"`

	TransitPath types.String `tfsdk:"transit_path"`
	TransitKey  types.String `tfsdk:"transit_key"`
	KVPath      types.String `tfsdk:"kv_path"`
	ManagedBy   types.String `tfsdk:"managed_by"`
}

func (p *Provider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "vault-secrets-as-code"
	resp.Version = p.version
}

func (p *Provider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	vaultConfigSchema := schema.ObjectAttribute{
		AttributeTypes: map[string]attr.Type{
			"endpoint": types.StringType,

			// TODO(antoine): mTLS
			// "ca":   types.StringType,
			// "cert": types.StringType,
			// "key":  types.StringType,

			"token": types.StringType,
		},
		Required: true,
	}
	// TODO(antoine): make sure extra / in paths are not an issue
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"transit_vault_config": vaultConfigSchema,
			"kv_vault_config":      vaultConfigSchema,
			"transit_path": schema.StringAttribute{
				Required: true,
			},
			"transit_key": schema.StringAttribute{
				Required: true,
			},
			"kv_path": schema.StringAttribute{
				Required: true,
			},
			"managed_by": schema.StringAttribute{
				Required: true,
			},
		},
	}
}

type ProviderData struct {
	transit vaultTransit
	kv      vaultKV
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data ProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	transitVaultConfig := VaultConfigModel{}
	KVVaultConfig := VaultConfigModel{}
	resp.Diagnostics.Append(data.TransitVaultConfig.As(ctx, &transitVaultConfig, basetypes.ObjectAsOptions{})...)
	resp.Diagnostics.Append(data.KVVaultConfig.As(ctx, &KVVaultConfig, basetypes.ObjectAsOptions{})...)

	transitVaultClient, err := newClient(transitVaultConfig)
	if err != nil {
		resp.Diagnostics.AddError("failed to setup transit vault client", err.Error())
		return
	}

	targetVaultClient, err := newClient(KVVaultConfig)
	if err != nil {
		resp.Diagnostics.AddError("failed to setup KV vault client", err.Error())
		return
	}

	resp.ResourceData = ProviderData{
		transit: vaultTransit{
			client: transitVaultClient,
			path:   data.TransitPath.ValueString(),
			key:    data.TransitKey.ValueString(),
		},
		kv: vaultKV{
			client:    targetVaultClient,
			path:      data.KVPath.ValueString(),
			managedBy: data.ManagedBy.ValueString(),
		},
	}
}

func (p *Provider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewSecretResource,
	}
}

func (p *Provider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &Provider{
			version: version,
		}
	}
}
