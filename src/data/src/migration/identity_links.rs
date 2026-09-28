//! Cross-database transfer preserves every link, original audit and reauthentication proof.
use crate::database::DB;
use crate::entity::identity_link_audit::IdentityLinkAudit;
use crate::entity::identity_link_intents::LinkIntent;
use crate::entity::identity_links::IdentityLink;
use crate::migration::identity_link_format::{self, FormatVersion};
use hiqlite::macros::params;
use rauthy_common::is_hiqlite;
use rauthy_derive::FromPgRow;
use rauthy_error::{ErrorResponse, ErrorResponseType};
use serde::Deserialize;

#[derive(Deserialize, FromPgRow)]
struct SessionProof {
    id: String,
    identity_link_auth_proof: Option<String>,
    identity_link_auth_at: Option<i64>,
}

pub(super) struct IdentityTransfer {
    audits: Vec<IdentityLinkAudit>,
    links: Vec<IdentityLink>,
    intents: Vec<LinkIntent>,
    proofs: Vec<SessionProof>,
}

fn read_sqlite<T: for<'a> Deserialize<'a>>(
    connection: &rusqlite::Connection,
    query: &str,
) -> Result<Vec<T>, ErrorResponse> {
    let mut statement = connection.prepare(query)?;
    let rows = statement.query([])?;
    serde_rusqlite::from_rows(rows)
        .collect::<Result<Vec<T>, _>>()
        .map_err(|error| {
            ErrorResponse::new(
                ErrorResponseType::Internal,
                format!("identity link transfer refused while reading {query}: {error}"),
            )
        })
}

impl IdentityTransfer {
    // Read all evidence before the destination migration mutates any family.
    pub(super) fn from_sqlite(connection: &rusqlite::Connection) -> Result<Self, ErrorResponse> {
        let format: Vec<FormatVersion> = read_sqlite(connection, "SELECT version FROM identity_link_format WHERE id=1")
            .map_err(|error| ErrorResponse::new(ErrorResponseType::BadRequest, format!("identity link transfer requires an upgraded source with identity_link_format: {}", error.message)))?;
        identity_link_format::validate(&format)?;
        Ok(Self {
            audits: read_sqlite(connection, "SELECT * FROM identity_link_audit")?,
            links: read_sqlite(connection, "SELECT * FROM identity_links")?,
            intents: read_sqlite(connection, "SELECT * FROM identity_link_intents")?,
            proofs: read_sqlite(connection, "SELECT * FROM sessions")?,
        })
    }

    pub(super) async fn from_postgres(
        connection: &deadpool_postgres::Client,
    ) -> Result<Self, ErrorResponse> {
        let format: Vec<FormatVersion> = DB::pg_query_map_with(connection, "SELECT version FROM identity_link_format WHERE id=1", &[], 1).await
            .map_err(|error| ErrorResponse::new(ErrorResponseType::BadRequest, format!("identity link transfer requires an upgraded source with identity_link_format: {}", error.message)))?;
        identity_link_format::validate(&format)?;
        Ok(Self {
            audits: DB::pg_query_map_with(
                connection,
                if format.first().is_some_and(|row| row.version == 1) {
                    "SELECT *, FALSE AS receipt_verified FROM identity_link_audit"
                } else {
                    "SELECT * FROM identity_link_audit"
                },
                &[],
                0,
            )
            .await?,
            links: DB::pg_query_map_with(connection, "SELECT * FROM identity_links", &[], 0)
                .await?,
            intents: DB::pg_query_map_with(
                connection,
                "SELECT * FROM identity_link_intents",
                &[],
                0,
            )
            .await?,
            proofs: DB::pg_query_map_with(connection, "SELECT * FROM sessions", &[], 0).await?,
        })
    }

    pub(super) async fn write(self) -> Result<(), ErrorResponse> {
        let audits_sql = "INSERT INTO identity_link_audit (id,user_id,provider_id,issuer,federation_uid,link_change,actor_session,observer,observed_at,lys_person,receipt,acknowledged_at,receipt_verified) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)";
        let links_sql = "INSERT INTO identity_links (provider_id,federation_uid,user_id,created) VALUES ($1,$2,$3,$4)";
        let intents_sql = "INSERT INTO identity_link_intents (id,user_id,session_id,provider_id,callback_id,nonce,created_at,expires_at,prior_auth_proof,reauthenticated_at,consumed_operation_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)";
        let proofs_sql =
            "UPDATE sessions SET identity_link_auth_proof=$1,identity_link_auth_at=$2 WHERE id=$3";
        let clear = [
            "DELETE FROM identity_link_intents",
            "DELETE FROM identity_links",
            "DELETE FROM identity_link_audit",
        ];
        if is_hiqlite() {
            let mut statements = Vec::new();
            for statement in clear {
                statements.push((statement, params!()));
            }
            for row in self.audits {
                statements.push((
                    audits_sql,
                    params!(
                        row.id,
                        row.user_id,
                        row.provider_id,
                        row.issuer,
                        row.federation_uid,
                        row.link_change,
                        row.actor_session,
                        row.observer,
                        row.observed_at,
                        row.lys_person,
                        row.receipt,
                        row.acknowledged_at,
                        row.receipt_verified
                    ),
                ));
            }
            for row in self.links {
                statements.push((
                    links_sql,
                    params!(
                        row.provider_id,
                        row.federation_uid,
                        row.user_id,
                        row.created
                    ),
                ));
            }
            for row in self.intents {
                statements.push((
                    intents_sql,
                    params!(
                        row.id,
                        row.user_id,
                        row.session_id,
                        row.provider_id,
                        row.callback_id,
                        row.nonce,
                        row.created_at,
                        row.expires_at,
                        row.prior_auth_proof,
                        row.reauthenticated_at,
                        row.consumed_operation_id
                    ),
                ));
            }
            for row in self.proofs {
                statements.push((
                    proofs_sql,
                    params!(
                        row.identity_link_auth_proof,
                        row.identity_link_auth_at,
                        row.id
                    ),
                ));
            }
            for result in DB::hql().txn(statements).await? {
                result?;
            }
        } else {
            let mut connection = DB::pg().await?;
            let transaction = connection.transaction().await?;
            for statement in clear {
                DB::pg_txn_append(&transaction, statement, &[]).await?;
            }
            for row in self.audits {
                DB::pg_txn_append(
                    &transaction,
                    audits_sql,
                    &[
                        &row.id,
                        &row.user_id,
                        &row.provider_id,
                        &row.issuer,
                        &row.federation_uid,
                        &row.link_change,
                        &row.actor_session,
                        &row.observer,
                        &row.observed_at,
                        &row.lys_person,
                        &row.receipt,
                        &row.acknowledged_at,
                        &row.receipt_verified,
                    ],
                )
                .await?;
            }
            for row in self.links {
                DB::pg_txn_append(
                    &transaction,
                    links_sql,
                    &[
                        &row.provider_id,
                        &row.federation_uid,
                        &row.user_id,
                        &row.created,
                    ],
                )
                .await?;
            }
            for row in self.intents {
                DB::pg_txn_append(
                    &transaction,
                    intents_sql,
                    &[
                        &row.id,
                        &row.user_id,
                        &row.session_id,
                        &row.provider_id,
                        &row.callback_id,
                        &row.nonce,
                        &row.created_at,
                        &row.expires_at,
                        &row.prior_auth_proof,
                        &row.reauthenticated_at,
                        &row.consumed_operation_id,
                    ],
                )
                .await?;
            }
            for row in self.proofs {
                DB::pg_txn_append(
                    &transaction,
                    proofs_sql,
                    &[
                        &row.identity_link_auth_proof,
                        &row.identity_link_auth_at,
                        &row.id,
                    ],
                )
                .await?;
            }
            transaction.commit().await?;
        }
        Ok(())
    }
}
