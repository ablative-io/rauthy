use crate::cust_validation::validate_vec_scopes;
use rauthy_common::regex::{
    RE_ALNUM, RE_ATPROTO_HANDLE, RE_CLIENT_ID, RE_CLIENT_NAME, RE_CODE_CHALLENGE, RE_SCOPE_SPACE,
    RE_URI,
};
use rauthy_derive::FromPgRow;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthProviderType {
    Custom,
    GitHub,
    Google,
    OIDC,
}

#[derive(Deserialize, Validate, ToSchema)]
pub struct ProviderRequest {
    /// Validation: `[a-zA-Z0-9À-ÿ-\s]{2,128}]`
    #[validate(regex(path = "*RE_CLIENT_NAME", code = "[a-zA-Z0-9À-ɏ-\\s]{2,128}"))]
    pub name: String,
    pub typ: AuthProviderType,
    pub enabled: bool,

    /// Validation: `[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]"))]
    pub issuer: String,
    /// Validation: `[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]"))]
    pub authorization_endpoint: String,
    /// Validation: `[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]"))]
    pub token_endpoint: String,
    /// Validation: `[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]"))]
    pub userinfo_endpoint: String,
    /// Validation: `[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]"))]
    pub jwks_endpoint: Option<String>,

    pub use_pkce: bool,
    pub client_secret_basic: bool,
    pub client_secret_post: bool,
    pub auto_onboarding: bool,
    pub auto_link: bool,

    // This validation is pretty loose, but if we make it too strict,
    // we will most probably get into compatibility issues.
    /// Validation: `[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]"))]
    pub client_id: String,
    /// Validation: max length is 256
    #[validate(length(max = 256))]
    pub client_secret: Option<String>,
    /// Validation: `[a-zA-Z0-9-_/:\s*]{0,512}`
    #[validate(regex(path = "*RE_SCOPE_SPACE", code = "[a-zA-Z0-9-_/:\\s*]{0,512}"))]
    pub scope: String,

    /// Validation: `[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]"))]
    pub admin_claim_path: Option<String>,
    /// Validation: `[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]"))]
    pub admin_claim_value: Option<String>,
    /// Validation: `[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]"))]
    pub mfa_claim_path: Option<String>,
    /// Validation: `[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]"))]
    pub mfa_claim_value: Option<String>,
}

#[derive(Deserialize, Validate, ToSchema)]
#[cfg_attr(debug_assertions, derive(Serialize))]
pub struct ProviderCallbackRequest {
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$"))]
    pub state: String,
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$"))]
    pub code: String,
    /// Validation: `[a-zA-Z0-9]`
    #[validate(regex(path = "*RE_ALNUM", code = "[a-zA-Z0-9]"))]
    pub xsrf_token: String,
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$"))]
    pub pkce_verifier: String,

    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$"))]
    pub iss_atproto: Option<String>,
}

#[derive(Deserialize, Validate, ToSchema)]
#[cfg_attr(debug_assertions, derive(Serialize))]
pub struct ProviderLoginRequest {
    // values for the downstream client
    /// Validation: `email`
    #[validate(email)]
    pub email: Option<String>,
    /// Validation: `^[a-zA-Z0-9,.:/_\-&?=~#!$'()*+%]{2,128}$`
    #[validate(regex(
        path = "*RE_CLIENT_ID",
        code = "^[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]{2,128}$"
    ))]
    pub client_id: String,
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$"))]
    pub redirect_uri: String,
    /// Validation: `Vec<^[a-z0-9-_/,:*]{2,64}$>`
    #[validate(custom(function = "validate_vec_scopes"))]
    pub scopes: Option<Vec<String>>,
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$"))]
    pub state: Option<String>,
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$"))]
    pub nonce: Option<String>,
    /// Validation: `[a-zA-Z0-9-._~]{43,128}`
    #[validate(regex(path = "*RE_CODE_CHALLENGE", code = "[a-zA-Z0-9-._~]{43,128}"))]
    pub code_challenge: Option<String>,
    /// Validation: `[a-zA-Z0-9]`
    #[validate(regex(path = "*RE_ALNUM", code = "[a-zA-Z0-9]"))]
    pub code_challenge_method: Option<String>,
    /// Validation: `^[a-zA-Z0-9,.:/_\-&?=~#!$'()*+%]{2,128}$`
    #[validate(regex(
        path = "*RE_CLIENT_ID",
        code = "^[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]{2,128}$"
    ))]
    pub pow: String,

    // values for the callback from upstream
    /// Validation: `[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]"))]
    pub provider_id: String,
    /// Validation: `[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_-&?=~#!$'()*+%@]+$"))]
    pub pkce_challenge: String,

    /// Validation:
    /// `^(did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]|([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)$`
    #[validate(regex(
        path = "*RE_ATPROTO_HANDLE",
        code = "^(did:[a-z]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]|([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)$"
    ))]
    pub handle: Option<String>,
}

#[derive(Deserialize, Validate, ToSchema)]
pub struct ProviderLookupRequest {
    /// Validation: `[a-zA-Z0-9,.:/_\-&?=~#!$'()*+%]`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]"))]
    pub issuer: Option<String>,
    /// Validation: `[a-zA-Z0-9,.:/_\-&?=~#!$'()*+%]`
    #[validate(regex(path = "*RE_URI", code = "[a-zA-Z0-9,.:/_\\-&?=~#!$'()*+%]"))]
    pub metadata_url: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ProviderResponse {
    pub id: String,
    pub name: String,
    pub typ: AuthProviderType,
    pub enabled: bool,

    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_endpoint: Option<String>,

    pub client_id: String,
    pub client_secret: Option<String>,
    pub scope: String,

    pub admin_claim_path: Option<String>,
    pub admin_claim_value: Option<String>,
    pub mfa_claim_path: Option<String>,
    pub mfa_claim_value: Option<String>,

    pub use_pkce: bool,
    pub client_secret_basic: bool,
    pub client_secret_post: bool,
    pub auto_onboarding: bool,
    pub auto_link: bool,
}

#[derive(Serialize, Deserialize, FromPgRow, ToSchema)]
pub struct ProviderLinkedUserResponse {
    pub id: String,
    pub email: String,
}

/// One upstream provider identity linked to the signed-in user.
#[derive(Serialize, ToSchema)]
pub struct ProviderLinkResponse {
    pub provider_id: String,
    pub provider_name: String,
    /// The provider's own subject for this identity.
    pub federation_uid: String,
    /// Unix timestamp in seconds
    pub created: i64,
    /// The oldest link, which the account's single provider fields show.
    pub primary: bool,
    /// Whether the receiver has acknowledged the audit of this link.
    pub audit: ProviderLinkAuditState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProviderLinkAuditState {
    Pending,
    Acknowledged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProviderLinkChange {
    Linked,
    Unlinked,
}

/// One link or unlink observation, as the audit receiver reads it.
#[derive(Serialize, ToSchema)]
pub struct ProviderLinkAuditResponse {
    /// Stable across every delivery: the receiver deduplicates on it.
    pub source_operation_id: String,
    /// The Rauthy user the login belongs to.
    pub user_id: String,
    pub change: ProviderLinkChange,
    pub provider_id: String,
    /// The upstream provider's issuer, which names the linked login with `subject`.
    pub issuer: String,
    /// The upstream provider's subject for the linked login.
    pub subject: String,
    /// This Rauthy instance's issuer, which observed the change.
    pub observer: String,
    /// Unix timestamp in seconds
    pub observed_at: i64,
    pub state: ProviderLinkAuditState,
    pub receipt: Option<String>,
    /// Unix timestamp in seconds
    pub acknowledged_at: Option<i64>,
}

#[derive(Deserialize, Validate, ToSchema)]
#[cfg_attr(debug_assertions, derive(Serialize))]
pub struct ProviderLinkAuditAckRequest {
    /// The receiver's receipt for the observation.
    ///
    /// Validation: 1 to 16384 bytes of printable ASCII
    #[validate(length(min = 1, max = 16384))]
    pub receipt: String,
}

#[derive(Serialize, ToSchema)]
pub struct ProviderLookupResponse {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_endpoint: Option<String>,
    pub scope: String,
    pub use_pkce: bool,
    pub client_secret_basic: bool,
    pub client_secret_post: bool,
}
