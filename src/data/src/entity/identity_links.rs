//! Provider identity lookup distinguishes absent identities from failed authoritative reads.
use std::future::Future;

/// Which authoritative lookup found the user; an email match is not a link grant.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IdentityLookup<User> {
    Linked(User),
    Email(User),
    Absent,
}

/// Why the authenticated linking target cannot accept this callback.
#[derive(Debug, PartialEq, Eq)]
pub enum LinkTargetRefusal {
    ProviderMismatch,
    IdentityAlreadyOwned,
    SessionNotAuthenticated,
    SessionOwnerMismatch,
}

/// Check the requested link even when the provider identity is already known.
///
/// # Errors
/// Refuses a different provider or an identity already owned by another user.
pub fn validate_link_target(
    provider: &str,
    owner: &str,
    requested_provider: &str,
    requested_owner: &str,
) -> Result<(), LinkTargetRefusal> {
    validate_link_provider(provider, requested_provider)?;
    if owner != requested_owner {
        return Err(LinkTargetRefusal::IdentityAlreadyOwned);
    }
    Ok(())
}

/// Keep the selected provider bound to the route and subsequent callback.
///
/// # Errors
/// Refuses a request or callback naming a different provider.
pub fn validate_link_provider(
    provider: &str,
    requested_provider: &str,
) -> Result<(), LinkTargetRefusal> {
    if provider != requested_provider {
        return Err(LinkTargetRefusal::ProviderMismatch);
    }
    Ok(())
}

/// A retained linking cookie cannot authorize a different or signed-out session.
///
/// # Errors
/// Refuses an unauthenticated session or a session not owned by the link target.
pub fn validate_link_session(
    authenticated: bool,
    session_owner: Option<&str>,
    requested_owner: &str,
) -> Result<(), LinkTargetRefusal> {
    if !authenticated {
        return Err(LinkTargetRefusal::SessionNotAuthenticated);
    }
    if session_owner != Some(requested_owner) {
        return Err(LinkTargetRefusal::SessionOwnerMismatch);
    }
    Ok(())
}

/// Read the provider identity before considering an email candidate.
pub(crate) async fn lookup_identity<User, Error, Federation, Email, EmailResult>(
    federation: Federation,
    email: Email,
) -> Result<IdentityLookup<User>, Error>
where
    Federation: Future<Output = Result<Option<User>, Error>>,
    Email: FnOnce() -> EmailResult,
    EmailResult: Future<Output = Result<Option<User>, Error>>,
{
    match federation.await? {
        Some(user) => Ok(IdentityLookup::Linked(user)),
        None => match email().await? {
            Some(user) => Ok(IdentityLookup::Email(user)),
            None => Ok(IdentityLookup::Absent),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IdentityLookup, LinkTargetRefusal, lookup_identity, validate_link_session,
        validate_link_target,
    };
    use std::cell::Cell;
    use std::future::{Future, ready};
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    fn poll_ready<Value>(future: impl Future<Output = Value>) -> Poll<Value> {
        pin!(future).poll(&mut Context::from_waker(Waker::noop()))
    }

    // ID001_LINK_REFUSAL: an unavailable provider lookup cannot fall back to email.
    #[test]
    fn provider_read_failure_does_not_consult_email() {
        let called = Cell::new(false);
        let result = poll_ready(lookup_identity(
            ready(Err::<Option<&str>, _>("provider store unreadable")),
            || {
                called.set(true);
                ready(Ok(Some("other person")))
            },
        ));
        assert_eq!(result, Poll::Ready(Err("provider store unreadable")));
        assert!(!called.get());
    }

    // ID001_LINK_REFUSAL: failed email lookup cannot authorize onboarding a new user.
    #[test]
    fn email_read_failure_is_not_absence() {
        let result = poll_ready(lookup_identity(ready(Ok(None::<&str>)), || {
            ready(Err("email store unreadable"))
        }));
        assert_eq!(result, Poll::Ready(Err("email store unreadable")));
    }

    #[test]
    fn existing_provider_identity_does_not_consult_email() {
        let called = Cell::new(false);
        let result = poll_ready(lookup_identity(
            ready(Ok::<_, &str>(Some("original person"))),
            || {
                called.set(true);
                ready(Ok(Some("other person")))
            },
        ));
        assert_eq!(
            result,
            Poll::Ready(Ok(IdentityLookup::Linked("original person")))
        );
        assert!(!called.get());
    }

    #[test]
    fn email_candidate_is_distinct_from_linked_identity() {
        let result = poll_ready(lookup_identity(ready(Ok::<_, &str>(None)), || {
            ready(Ok(Some("email candidate")))
        }));
        assert_eq!(
            result,
            Poll::Ready(Ok(IdentityLookup::Email("email candidate")))
        );
    }

    #[test]
    fn two_successful_absent_reads_allow_onboarding_policy_to_decide() {
        let result = poll_ready(lookup_identity(
            ready(Ok::<Option<&str>, &str>(None)),
            || ready(Ok(None)),
        ));
        assert_eq!(result, Poll::Ready(Ok(IdentityLookup::Absent)));
    }

    // ID001_LINK_REFUSAL: a known upstream identity never switches the requested person.
    #[test]
    fn linked_identity_owned_by_another_person_is_refused() {
        assert_eq!(
            validate_link_target("google", "person-a", "google", "person-b"),
            Err(LinkTargetRefusal::IdentityAlreadyOwned),
        );
    }

    #[test]
    fn linked_identity_cannot_satisfy_another_provider_intent() {
        assert_eq!(
            validate_link_target("google", "person-a", "github", "person-a"),
            Err(LinkTargetRefusal::ProviderMismatch),
        );
    }

    #[test]
    fn exact_provider_and_person_pass_target_check() {
        assert_eq!(
            validate_link_target("google", "person-a", "google", "person-a"),
            Ok(()),
        );
    }

    #[test]
    fn retained_link_intent_cannot_be_used_after_sign_out() {
        assert_eq!(
            validate_link_session(false, Some("person-a"), "person-a"),
            Err(LinkTargetRefusal::SessionNotAuthenticated),
        );
    }

    #[test]
    fn retained_link_intent_cannot_be_used_by_another_session_owner() {
        assert_eq!(
            validate_link_session(true, Some("person-b"), "person-a"),
            Err(LinkTargetRefusal::SessionOwnerMismatch),
        );
        assert_eq!(
            validate_link_session(true, None, "person-a"),
            Err(LinkTargetRefusal::SessionOwnerMismatch),
        );
    }

    #[test]
    fn authenticated_target_session_passes_session_check() {
        assert_eq!(
            validate_link_session(true, Some("person-a"), "person-a"),
            Ok(())
        );
    }
}
