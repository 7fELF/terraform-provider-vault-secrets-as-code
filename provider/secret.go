package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &SecretResource{}
	_ resource.ResourceWithImportState = &SecretResource{}
)

func NewSecretResource() resource.Resource {
	return &SecretResource{}
}

// SecretResource defines the resource implementation.
type SecretResource struct {
	ProviderData
}

// SecretModel describes the resource data model.
type SecretModel struct {
	Path             string            `tfsdk:"path"`
	EncryptedSecrets map[string]string `tfsdk:"encrypted_secrets"`
}

func (r *SecretResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *SecretResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Secret",
		Attributes: map[string]schema.Attribute{
			"path": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"encrypted_secrets": schema.MapAttribute{Required: true, ElementType: types.StringType},
		},
	}
}

func (r *SecretResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	providerData, ok := req.ProviderData.(ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected ProviderData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.ProviderData = providerData
}

func (r *SecretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data SecretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	decrypted := make(map[string]any)
	for k, v := range data.EncryptedSecrets {
		res, err := r.transit.Decrypt(ctx, v)
		if err != nil {
			resp.Diagnostics.AddError("failed to decrypt secret", err.Error())
			return
		}
		decrypted[k] = res
	}

	err := r.kv.Put(ctx, data.Path, decrypted)
	if err != nil {
		resp.Diagnostics.AddError("failed to decrypt secret", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *SecretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data SecretModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	decrypted := make(map[string]string)
	for k, v := range data.EncryptedSecrets {
		res, err := r.transit.Decrypt(ctx, v)
		if err != nil {
			resp.Diagnostics.AddError("failed to decrypt secret ", err.Error())
			return
		}
		decrypted[k] = res
	}

	kv, err := r.kv.client.KVv2(r.kv.path).Get(ctx, data.Path)
	if err != nil {
		resp.Diagnostics.AddError("failed to get secret", err.Error())
		return
	}

	dataout := make(map[string]string)
	for k, v := range kv.Data {
		if value, ok := decrypted[k]; ok && value == v {
			dataout[k] = data.EncryptedSecrets[k]
		} else {
			dataout[k], err = r.transit.Encrypt(ctx, v.(string))
			if err != nil {
				resp.Diagnostics.AddError("failed encrypt secret", err.Error())
				return
			}

		}
	}

	data.EncryptedSecrets = dataout

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *SecretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan SecretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	decrypted := make(map[string]any)
	for k, v := range plan.EncryptedSecrets {
		res, err := r.transit.Decrypt(ctx, v)
		if err != nil {
			resp.Diagnostics.AddError("failed to decrypt secret", err.Error())
			return
		}
		decrypted[k] = res
	}

	err := r.kv.Put(ctx, plan.Path, decrypted)
	if err != nil {
		resp.Diagnostics.AddError("failed to decrypt secret", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *SecretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data SecretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.kv.Destroy(ctx, data.Path); err != nil {
		resp.Diagnostics.AddError("failed to delete secret: ", err.Error())
	}

	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *SecretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	data := SecretModel{
		Path: req.ID,
	}

	err := r.kv.OverwriteManagedbyMeta(ctx, data.Path)
	if err != nil {
		resp.Diagnostics.AddError("failed to mark secret as managed by Terraform", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
