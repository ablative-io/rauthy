use crate::rauthy_config::RauthyConfig;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::dev::ServiceRequest;
use actix_web::{HttpRequest, cookie};
use cryptr::EncValue;
use rauthy_common::constants::CookieMode;
use rauthy_common::utils::{base64_decode, base64_encode};
use rauthy_error::{ErrorResponse, ErrorResponseType};
use std::borrow::Cow;
use std::fmt::Display;
use tracing::warn;

pub struct ApiCookie;

impl ApiCookie {
    /// Read an optional cookie without turning malformed authentication into absence.
    ///
    /// # Errors
    /// Names the cookie when decoding, authentication or UTF-8 validation fails.
    pub fn from_req_checked(
        req: &HttpRequest,
        cookie_name: &str,
    ) -> Result<Option<String>, ErrorResponse> {
        let name = match RauthyConfig::get().vars.access.cookie_mode {
            CookieMode::Host => format!("__Host-{cookie_name}"),
            CookieMode::Secure => format!("__Secure-{cookie_name}"),
            CookieMode::DangerInsecure => cookie_name.to_owned(),
        };
        Self::cookie_into_value_checked(req.cookie(&name)).map_err(|error| {
            ErrorResponse::new(
                ErrorResponseType::Forbidden,
                format!(
                    "invalid authenticated cookie '{cookie_name}': {}",
                    error.error
                ),
            )
        })
    }

    fn cookie_into_value_checked(
        cookie: Option<Cookie<'_>>,
    ) -> Result<Option<String>, ErrorResponse> {
        let Some(cookie) = cookie else {
            return Ok(None);
        };
        let bytes = base64_decode(cookie.value())?;
        let encrypted = EncValue::try_from(bytes)?;
        let cleartext = encrypted.decrypt()?;
        let text = std::str::from_utf8(cleartext.as_ref()).map_err(|error| {
            ErrorResponse::new(
                ErrorResponseType::BadRequest,
                format!("authenticated cookie is not UTF-8: {error}"),
            )
        })?;
        Ok(Some(text.to_owned()))
    }

    pub fn build<'c, 'b, N, V>(name: N, value: V, max_age: i64) -> Cookie<'c>
    where
        N: Into<Cow<'c, str>> + Display,
        V: Into<Cow<'b, str>> + Display,
    {
        Self::build_with_same_site(name, value, max_age, SameSite::Lax)
    }

    pub fn build_with_same_site<'c, 'b, N, V>(
        name: N,
        value: V,
        max_age: i64,
        same_site: SameSite,
    ) -> Cookie<'c>
    where
        N: Into<Cow<'c, str>> + Display,
        V: Into<Cow<'b, str>> + Display,
    {
        let access = &RauthyConfig::get().vars.access;
        let path = if access.cookie_set_path { "/auth" } else { "/" };
        let (name, secure, path) = match access.cookie_mode {
            CookieMode::Host => (format!("__Host-{name}"), true, "/"),
            CookieMode::Secure => (format!("__Secure-{name}"), true, path),
            CookieMode::DangerInsecure => {
                warn!("Building INSECURE cookie - you MUST NEVER use this in production");
                (name.to_string(), false, path)
            }
        };
        let max_age = if max_age < 1 {
            cookie::time::Duration::ZERO
        } else {
            cookie::time::Duration::seconds(max_age)
        };

        // we always encrypt any cookie value
        let enc =
            EncValue::encrypt(value.into().as_bytes()).expect("ENC_VALUES not set up correctly");
        let value_b64 = base64_encode(enc.into_bytes().as_ref());

        Cookie::build(name, value_b64)
            .secure(secure)
            .http_only(true)
            .same_site(same_site)
            .max_age(max_age)
            .path(path)
            .finish()
    }

    pub fn from_req<'c, N>(req: &HttpRequest, cookie_name: N) -> Option<String>
    where
        N: Into<Cow<'c, str>> + Display,
    {
        let name = match RauthyConfig::get().vars.access.cookie_mode {
            CookieMode::Host => format!("__Host-{cookie_name}"),
            CookieMode::Secure => format!("__Secure-{cookie_name}"),
            CookieMode::DangerInsecure => cookie_name.to_string(),
        };
        // req.cookie(&name)
        Self::cookie_into_value(req.cookie(&name))
    }

    pub fn from_svc_req<'c, N>(req: &ServiceRequest, cookie_name: N) -> Option<String>
    where
        N: Into<Cow<'c, str>> + Display,
    {
        let name = match RauthyConfig::get().vars.access.cookie_mode {
            CookieMode::Host => format!("__Host-{cookie_name}"),
            CookieMode::Secure => format!("__Secure-{cookie_name}"),
            CookieMode::DangerInsecure => cookie_name.to_string(),
        };
        Self::cookie_into_value(req.cookie(&name))
    }

    pub fn cookie_into_value(cookie: Option<Cookie>) -> Option<String> {
        match cookie {
            None => None,
            Some(cookie) => {
                let val = cookie.value();
                let bytes = base64_decode(val).ok()?;
                let enc = EncValue::try_from(bytes).ok()?;
                let dec = enc.decrypt().ok()?;
                Some(String::from_utf8_lossy(dec.as_ref()).to_string())
            }
        }
    }
}

#[cfg(test)]
mod checked_tests {
    use super::ApiCookie;
    use actix_web::cookie::Cookie;

    #[test]
    fn id001_link_refusal_absent_cookie_is_distinct_from_corrupt_cookie() {
        assert_eq!(ApiCookie::cookie_into_value_checked(None), Ok(None));
        assert!(ApiCookie::cookie_into_value_checked(Some(Cookie::new("link", "%%%"))).is_err());
        assert!(
            ApiCookie::cookie_into_value_checked(Some(Cookie::new("link", "aW52YWxpZA==")))
                .is_err()
        );
    }
}
