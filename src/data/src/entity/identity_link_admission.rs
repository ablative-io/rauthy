//! Authoritative provider relations and one-transaction link admission; no email-based authority.
use crate::database::DB;
use crate::entity::identity_link_sql;
use rauthy_error::{ErrorResponse, ErrorResponseType};

/// Exact callback evidence; admission additionally checks the durable intent and session.
pub struct LinkAdmission<'a> {
    pub operation_id: &'a str,
    pub intent_id: &'a str,
    pub user_id: &'a str,
    pub session_id: &'a str,
    pub provider_id: &'a str,
    pub callback_id: &'a str,
    pub nonce: &'a str,
    pub issuer: &'a str,
    pub subject: &'a str,
    pub observer: &'a str,
    pub observed_at: i64,
}

impl LinkAdmission<'_> {
    /// Consume the intent, append audit provenance and admit its link atomically.
    ///
    /// # Errors
    /// Names the operation and target on an expired/replayed/mismatched intent,
    /// collision or database failure. A transport failure may be indeterminate:
    /// callers must look up this exact operation, never mint a replacement ID.
    pub async fn commit(&self) -> Result<(), ErrorResponse> {
        match self.commit_inner().await {
            Ok(()) => Ok(()),
            Err(error) => {
                // A transport error can follow commit. Observe this exact original
                // operation before answering; never submit a replacement mutation.
                match crate::entity::identity_link_observation::LinkAudit::find(self.operation_id)
                    .await
                {
                    Ok(Some(original)) => {
                        original.matches_request(
                            self.user_id,
                            self.provider_id,
                            self.subject,
                            "linked",
                        )?;
                        if original.issuer != self.issuer
                            || original.actor_session != self.session_id
                            || original.observer != self.observer
                            || original.observed_at != self.observed_at
                        {
                            return Err(ErrorResponse::new(
                                rauthy_error::ErrorResponseType::Forbidden,
                                format!(
                                    "identity link operation '{}' has different original evidence",
                                    self.operation_id
                                ),
                            ));
                        }
                        Ok(())
                    }
                    Ok(None) => Err(ErrorResponse::new(
                        error.error,
                        format!(
                            "identity linked operation '{}' for user '{}' and provider '{}' was not committed: {}",
                            self.operation_id, self.user_id, self.provider_id, error.message
                        ),
                    )),
                    Err(read_error) => Err(ErrorResponse::new(
                        rauthy_error::ErrorResponseType::Internal,
                        format!(
                            "identity linked operation '{}' has an unconfirmed outcome; retain this id: write: {}; read-back: {}",
                            self.operation_id, error.message, read_error.message
                        ),
                    )),
                }
            }
        }
    }

    async fn commit_inner(&self) -> Result<(), ErrorResponse> {
        if self.subject.is_empty() || self.operation_id.is_empty() {
            return Err(ErrorResponse::new(
                ErrorResponseType::BadRequest,
                "identity link requires a nonempty subject and operation id",
            ));
        }
        {
            let mut connection = DB::pg().await?;
            let transaction = connection.transaction().await?;
            DB::pg_txn_append(
                &transaction,
                identity_link_sql::LOCK_PERSON,
                &[&self.user_id],
            )
            .await?;
            DB::pg_txn_append(
                &transaction,
                identity_link_sql::CONSUME,
                &[
                    &self.operation_id,
                    &self.intent_id,
                    &self.user_id,
                    &self.session_id,
                    &self.provider_id,
                    &self.callback_id,
                    &self.nonce,
                    &self.observed_at,
                ],
            )
            .await?;
            DB::pg_txn_append(
                &transaction,
                identity_link_sql::AUDIT_LINK,
                &[
                    &self.operation_id,
                    &self.intent_id,
                    &self.provider_id,
                    &self.issuer,
                    &self.subject,
                    &self.session_id,
                    &self.observer,
                    &self.observed_at,
                ],
            )
            .await?;
            DB::pg_txn_append(
                &transaction,
                identity_link_sql::INSERT_LINK,
                &[&self.operation_id],
            )
            .await?;
            DB::pg_txn_append(
                &transaction,
                identity_link_sql::PROJECT_PRIMARY,
                &[&self.user_id],
            )
            .await?;
            transaction.commit().await?;
        }
        Ok(())
    }
}
