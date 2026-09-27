-- Every upstream provider identity linked to a user. One provider identity names at most one
-- user, and a user holds at most one identity per provider. The single pair on `users` stays as
-- the user's oldest link, so every existing reader of it keeps working.
CREATE TABLE identity_links
(
    provider_id    VARCHAR NOT NULL
        CONSTRAINT identity_links_auth_providers_id_fk
            REFERENCES auth_providers
            ON UPDATE CASCADE ON DELETE CASCADE,
    federation_uid VARCHAR NOT NULL,
    user_id        VARCHAR NOT NULL
        CONSTRAINT identity_links_users_id_fk
            REFERENCES users
            ON DELETE CASCADE,
    created        BIGINT  NOT NULL,
    CONSTRAINT identity_links_pk
        PRIMARY KEY (provider_id, federation_uid),
    CONSTRAINT identity_links_user_provider_key
        UNIQUE (user_id, provider_id)
);

-- Existing links keep their user IDs: each user's single pair becomes its first link.
INSERT INTO identity_links (provider_id, federation_uid, user_id, created)
SELECT auth_provider_id, federation_uid, id, created_at
FROM users
WHERE auth_provider_id IS NOT NULL
  AND federation_uid IS NOT NULL;

-- The outbox of link and unlink observations. A row is written in the same transaction as the
-- change it records and stays pending until the receiver acknowledges it with a receipt.
CREATE TABLE identity_link_audit
(
    id              VARCHAR NOT NULL
        CONSTRAINT identity_link_audit_pk
            PRIMARY KEY,
    user_id         VARCHAR NOT NULL,
    provider_id     VARCHAR NOT NULL,
    issuer          VARCHAR NOT NULL,
    federation_uid  VARCHAR NOT NULL,
    link_change     VARCHAR NOT NULL,
    observed_at     BIGINT  NOT NULL,
    receipt         VARCHAR,
    acknowledged_at BIGINT
);

CREATE INDEX identity_link_audit_acknowledged_at_index
    ON identity_link_audit (acknowledged_at, observed_at);

CREATE INDEX identity_link_audit_user_id_index
    ON identity_link_audit (user_id);
