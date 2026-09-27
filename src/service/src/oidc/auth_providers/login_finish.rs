use crate::oidc;
use crate::oidc::authorize::AuthorizeData;
use actix_web::HttpRequest;
use actix_web::cookie::Cookie;
use rauthy_api_types::auth_providers::ProviderCallbackRequest;
use rauthy_common::constants::{COOKIE_UPSTREAM_CALLBACK, PROVIDER_ATPROTO};
use rauthy_common::sha256;
use rauthy_common::utils::base64_url_encode;
use rauthy_data::AuthStep;
use rauthy_data::api_cookie::ApiCookie;
use rauthy_data::entity::auth_providers::{
    AuthProvider, AuthProviderCallback, NewFederatedUserCreated, ProviderLinkIntent,
    ProviderMfaLogin,
};
use rauthy_data::entity::clients::Client;
use rauthy_data::entity::sessions::{Session, SessionState};
use rauthy_error::{ErrorResponse, ErrorResponseType};
use tracing::error;

/// The callback is single-use: it is deleted as soon as it has been validated.
pub async fn login_finish<'a>(
    req: &'a HttpRequest,
    payload: &'a ProviderCallbackRequest,
    mut session: Session,
) -> Result<(AuthStep, Cookie<'a>, NewFederatedUserCreated), ErrorResponse> {
    // the callback id for the cache should be inside the encrypted cookie
    let callback_id = ApiCookie::from_req(req, COOKIE_UPSTREAM_CALLBACK).ok_or_else(|| {
        ErrorResponse::new(
            ErrorResponseType::Forbidden,
            "Missing encrypted callback cookie",
        )
    })?;

    // validate state
    if payload.iss_atproto.is_none() && callback_id != payload.state {
        AuthProviderCallback::delete(callback_id).await?;

        error!("`state` does not match");
        return Err(ErrorResponse::new(
            ErrorResponseType::BadRequest,
            "`state` does not match",
        ));
    }

    // validate csrf token
    let slf = AuthProviderCallback::find(callback_id).await?;
    if slf.xsrf_token != payload.xsrf_token {
        AuthProviderCallback::delete(slf.callback_id).await?;

        error!("invalid CSRF token");
        return Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "invalid CSRF token",
        ));
    }

    // validate PKCE verifier
    let hash_base64 = base64_url_encode(sha256!(payload.pkce_verifier.as_bytes()));
    if slf.pkce_challenge != hash_base64 {
        AuthProviderCallback::delete(slf.callback_id).await?;

        error!("invalid PKCE verifier");
        return Err(ErrorResponse::new(
            ErrorResponseType::Unauthorized,
            "invalid PKCE verifier",
        ));
    }

    // The callback is validated at this point, so we can safely clean up the cache.
    AuthProviderCallback::delete(slf.callback_id.clone()).await?;

    // request is valid -> fetch token for the user
    let provider = AuthProvider::find(&slf.provider_id).await?;

    // A link is completed only in the session that asked for it, still signed in as the
    // account it names.
    if let Some(link) = &slf.link {
        check_link_session(link, &session)?;
    }

    // deserialize payload and validate the information
    let (user, provider_mfa_login, is_new_user) = if provider.issuer == PROVIDER_ATPROTO {
        slf.extract_user_at_proto(&provider, slf.link.as_ref(), payload)
            .await?
    } else {
        slf.extract_user(&provider, slf.link.as_ref(), payload)
            .await?
    };

    user.check_enabled()?;
    user.check_expired()?;

    if slf.link.is_some() {
        // If this is the case, we don't need to validate any further client values.
        // We will not generate a new auth code at all -> this is just a request to federate
        // an existing account. The federation has been done in the step above already.
        return Ok((
            AuthStep::ProviderLink,
            ApiCookie::build(COOKIE_UPSTREAM_CALLBACK, "", 0),
            is_new_user,
        ));
    }

    // From here on, we deal with a normal login instead of just an account federation.

    let require_webauthn = user.has_webauthn_enabled();
    session
        .set_mfa(provider_mfa_login == ProviderMfaLogin::Yes || require_webauthn)
        .await?;

    let client = Client::find_maybe_ephemeral(slf.req_client_id).await?;
    let header_origin = client.get_validated_origin_header(req)?;

    let auth_step = oidc::authorize::finish_authorize(
        user,
        client,
        &mut session,
        AuthorizeData {
            redirect_uri: slf.req_redirect_uri,
            scopes: slf.req_scopes,
            state: slf.req_state,
            nonce: slf.req_nonce,
            code_challenge: slf.req_code_challenge,
            code_challenge_method: slf.req_code_challenge_method,
            // brokered logins via an upstream IdP do not propagate RFC 8707 resource
            // indicators yet
            resource: None,
            header_origin,
            require_webauthn,
        },
        None,
        Some(provider_mfa_login),
    )
    .await?;

    // callback data deletion cookie
    let cookie = ApiCookie::build(COOKIE_UPSTREAM_CALLBACK, "", 0);

    Ok((auth_step, cookie, is_new_user))
}

/// Refuses a link callback unless `session` is the authenticated session that started the link
/// for the same account.
fn check_link_session(link: &ProviderLinkIntent, session: &Session) -> Result<(), ErrorResponse> {
    let same_session = session.id == link.session_id;
    let same_user = session.user_id.as_deref() == Some(link.user_id.as_str());
    let authenticated = session.state()? == SessionState::Auth;
    if same_session && same_user && authenticated {
        Ok(())
    } else {
        error!("provider link callback outside the session that started it");
        Err(ErrorResponse::new(
            ErrorResponseType::Forbidden,
            "identity_link_intent_mismatch: this link was started by another session or account",
        ))
    }
}
