-- Forward admission hardening; the existing provider relation and primary order stay intact.
-- Rust preflight names malformed user rows before migrations. This guard also refuses
-- direct migration application that would otherwise retain an unrepresented half-pair.
CREATE TABLE identity_link_migration_guard (ok BIGINT NOT NULL CHECK (ok=1));
INSERT INTO identity_link_migration_guard
SELECT 0 FROM users WHERE (auth_provider_id IS NULL AND federation_uid IS NOT NULL)
 OR (auth_provider_id IS NOT NULL AND federation_uid IS NULL);
DROP TABLE identity_link_migration_guard;

ALTER TABLE identity_link_audit ADD COLUMN actor_session TEXT;
ALTER TABLE identity_link_audit ADD COLUMN observer TEXT;
ALTER TABLE identity_link_audit ADD COLUMN lys_person TEXT;
ALTER TABLE sessions ADD COLUMN identity_link_auth_proof TEXT;
ALTER TABLE sessions ADD COLUMN identity_link_auth_at BIGINT;

CREATE TABLE identity_link_intents (
    id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL REFERENCES auth_providers(id) ON DELETE CASCADE,
    callback_id TEXT NOT NULL UNIQUE,
    nonce TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    prior_auth_proof TEXT,
    reauthenticated_at BIGINT,
    consumed_operation_id TEXT UNIQUE REFERENCES identity_link_audit(id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT identity_link_intent_lifetime CHECK (
        (reauthenticated_at IS NULL OR reauthenticated_at >= created_at) AND
        expires_at > created_at
    )
);

CREATE TABLE identity_link_format (id BIGINT PRIMARY KEY CHECK(id=1), version BIGINT NOT NULL);
INSERT INTO identity_link_format(id,version) VALUES (1,1);
