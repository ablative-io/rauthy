//! Transaction statements bind a single-use intent to its exact link and audit row.

/// Acquire the intent by conditional update, serialising concurrent callbacks.
/// The audit foreign key is deferred until the same transaction inserts its row.
pub const CONSUME: &str = "
UPDATE identity_link_intents SET consumed_operation_id = $1
WHERE id = $2 AND user_id = $3 AND session_id = $4 AND provider_id = $5
  AND callback_id = $6 AND nonce = $7 AND expires_at > $8
  AND reauthenticated_at IS NOT NULL
  AND consumed_operation_id IS NULL
  AND EXISTS (SELECT 1 FROM sessions s
      WHERE s.id = $4 AND s.user_id = $3 AND s.state = 'auth' AND s.exp > $8)
  AND EXISTS (SELECT 1 FROM users u WHERE u.id = $3 AND u.enabled = TRUE
      AND (u.user_expires IS NULL OR u.user_expires > $8))
  AND EXISTS (SELECT 1 FROM auth_providers p WHERE p.id = $5 AND p.enabled = TRUE)
";

/// Serialise mutations of one person's login methods on Postgres as well as SQLite.
pub const LOCK_PERSON: &str = "UPDATE users SET id=id WHERE id=$1";

/// Refuse removal unless a different enabled provider, usable password or passkey remains.
pub const AUDIT_UNLINK: &str = "WITH identity_args (p1,p2,p3,p4,p5,p6,p7,p8) AS (VALUES (CAST($1 AS VARCHAR),CAST($2 AS VARCHAR),CAST($3 AS VARCHAR),CAST($4 AS VARCHAR),CAST($5 AS VARCHAR),CAST($6 AS VARCHAR),CAST($7 AS VARCHAR),CAST($8 AS BIGINT)))

INSERT INTO identity_link_audit
(id,user_id,provider_id,issuer,federation_uid,link_change,actor_session,observer,observed_at)
VALUES ((SELECT p1 FROM identity_args),
 (SELECT u.id FROM users u WHERE u.id=(SELECT p2 FROM identity_args) AND u.enabled=TRUE
  AND (u.user_expires IS NULL OR u.user_expires>(SELECT p8 FROM identity_args))
  AND EXISTS (SELECT 1 FROM sessions s WHERE s.id=(SELECT p6 FROM identity_args) AND s.user_id=u.id AND s.state='auth' AND s.exp>(SELECT p8 FROM identity_args))
  AND EXISTS (SELECT 1 FROM identity_links l WHERE l.user_id=u.id AND l.provider_id=(SELECT p3 FROM identity_args) AND l.federation_uid=(SELECT p5 FROM identity_args))
  AND ((u.password IS NOT NULL AND (u.password_expires IS NULL OR u.password_expires>(SELECT p8 FROM identity_args)))
    OR EXISTS (SELECT 1 FROM passkeys k WHERE k.user_id=u.id)
    OR EXISTS (SELECT 1 FROM identity_links l JOIN auth_providers p ON p.id=l.provider_id
      WHERE l.user_id=u.id AND p.enabled=TRUE AND (l.provider_id<>(SELECT p3 FROM identity_args) OR l.federation_uid<>(SELECT p5 FROM identity_args))))),
 (SELECT p3 FROM identity_args),(SELECT p4 FROM identity_args),(SELECT p5 FROM identity_args),'unlinked',(SELECT p6 FROM identity_args),(SELECT p7 FROM identity_args),(SELECT p8 FROM identity_args))
";

pub const DELETE_LINK: &str = "DELETE FROM identity_links
WHERE user_id=$1 AND provider_id=$2 AND federation_uid=$3";

/// A zero-row intent claim becomes a NOT NULL refusal, rolling back the whole txn.
/// Do not change this to INSERT SELECT: that would silently accept no matching row.
pub const AUDIT_LINK: &str = "WITH identity_args (p1,p2,p3,p4,p5,p6,p7,p8) AS (VALUES (CAST($1 AS VARCHAR),CAST($2 AS VARCHAR),CAST($3 AS VARCHAR),CAST($4 AS VARCHAR),CAST($5 AS VARCHAR),CAST($6 AS VARCHAR),CAST($7 AS VARCHAR),CAST($8 AS BIGINT)))

INSERT INTO identity_link_audit
(id,user_id,provider_id,issuer,federation_uid,link_change,actor_session,observer,observed_at)
VALUES ((SELECT p1 FROM identity_args),
 (SELECT user_id FROM identity_link_intents WHERE id=(SELECT p2 FROM identity_args) AND consumed_operation_id=(SELECT p1 FROM identity_args)),
 (SELECT p3 FROM identity_args),(SELECT p4 FROM identity_args),(SELECT p5 FROM identity_args),'linked',(SELECT p6 FROM identity_args),(SELECT p7 FROM identity_args),(SELECT p8 FROM identity_args))
";

/// Unique (provider, subject) prevents reassignment, including concurrent owners.
pub const INSERT_LINK: &str = "
INSERT INTO identity_links(provider_id, federation_uid, user_id, created)
SELECT provider_id, federation_uid, user_id, observed_at
FROM identity_link_audit WHERE id = $1
";

/// The first provider account and its observation join the user insert transaction.
pub const AUDIT_ONBOARDING: &str = "WITH identity_args (p1,p2,p3,p4,p5) AS (VALUES (CAST($1 AS VARCHAR),CAST($2 AS VARCHAR),CAST($3 AS VARCHAR),CAST($4 AS VARCHAR),CAST($5 AS BIGINT)))

INSERT INTO identity_link_audit
(id,user_id,provider_id,issuer,federation_uid,link_change,actor_session,observer,observed_at)
SELECT (SELECT p1 FROM identity_args),u.id,u.auth_provider_id,p.issuer,u.federation_uid,'linked',(SELECT p3 FROM identity_args),(SELECT p4 FROM identity_args),(SELECT p5 FROM identity_args)
FROM users u JOIN auth_providers p ON p.id=u.auth_provider_id WHERE u.id=(SELECT p2 FROM identity_args)
";

/// Onboarding writes the same relation as the explicit link transaction.
pub const INSERT_ONBOARDING: &str = INSERT_LINK;

/// Preserve the remote's primary identity ordering and stability.
pub const PROJECT_PRIMARY: &str = super::identity_links::SQL_PRIMARY;

/// Capture the current proof in the same durable statement that prepares an intent.
pub const PREPARE_INTENT: &str = "WITH identity_args (p1,p2,p3,p4,p5,p6,p7,p8) AS (VALUES (CAST($1 AS VARCHAR),CAST($2 AS VARCHAR),CAST($3 AS VARCHAR),CAST($4 AS VARCHAR),CAST($5 AS VARCHAR),CAST($6 AS VARCHAR),CAST($7 AS BIGINT),CAST($8 AS BIGINT)))
INSERT INTO identity_link_intents
            (id,user_id,session_id,provider_id,callback_id,nonce,created_at,expires_at,prior_auth_proof)
            VALUES ((SELECT p1 FROM identity_args),
                (SELECT user_id FROM sessions WHERE id=(SELECT p3 FROM identity_args) AND user_id=(SELECT p2 FROM identity_args) AND state='auth' AND exp>(SELECT p7 FROM identity_args)),
                (SELECT p3 FROM identity_args),(SELECT p4 FROM identity_args),(SELECT p5 FROM identity_args),(SELECT p6 FROM identity_args),(SELECT p7 FROM identity_args),(SELECT p8 FROM identity_args),
                (SELECT identity_link_auth_proof FROM sessions WHERE id=(SELECT p3 FROM identity_args)))";

/// A refresh cannot activate an intent: the actual authentication proof must change.
pub const ACTIVATE_INTENT: &str = "WITH identity_args (p1,p2,p3,p4,p5) AS (VALUES (CAST($1 AS VARCHAR),CAST($2 AS VARCHAR),CAST($3 AS VARCHAR),CAST($4 AS VARCHAR),CAST($5 AS BIGINT)))
UPDATE identity_link_intents SET reauthenticated_at = (
            SELECT identity_link_auth_at FROM sessions s WHERE s.id=(SELECT p3 FROM identity_args) AND s.user_id=(SELECT p2 FROM identity_args)
                AND s.state='auth' AND s.exp>(SELECT p5 FROM identity_args) AND s.identity_link_auth_proof IS NOT NULL
                AND (prior_auth_proof IS NULL OR s.identity_link_auth_proof <> prior_auth_proof)
                AND s.identity_link_auth_at >= created_at)
            WHERE id=(SELECT p1 FROM identity_args) AND user_id=(SELECT p2 FROM identity_args) AND session_id=(SELECT p3 FROM identity_args) AND provider_id=(SELECT p4 FROM identity_args)
                AND expires_at>(SELECT p5 FROM identity_args) AND consumed_operation_id IS NULL";

/// Only credential ceremony completion calls this statement.
pub const RECORD_REAUTHENTICATION: &str =
    "UPDATE sessions SET identity_link_auth_proof=$1,identity_link_auth_at=$2
        WHERE id=$3 AND user_id=$4 AND state='auth' AND exp>$2";
