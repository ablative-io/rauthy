//! Provider-specific unlink preserves a usable method and commits audit evidence atomically.
use crate::database::DB;
use crate::entity::identity_link_sql;
use rauthy_error::ErrorResponse;

/// Original request identity and observed provider binding, retained through retries.
pub struct UnlinkAdmission<'a> {
    pub operation_id: &'a str,
    pub user_id: &'a str,
    pub session_id: &'a str,
    pub provider_id: &'a str,
    pub issuer: &'a str,
    pub subject: &'a str,
    pub observer: &'a str,
    pub observed_at: i64,
}

impl UnlinkAdmission<'_> {
    /// Remove this exact method; the SQL guard runs while holding the person lock.
    ///
    /// # Errors
    /// Refuses the final usable method, a missing method, revoked authority or a
    /// storage failure, naming the user, provider and original operation.
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
                            "unlinked",
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
                            "identity unlinked operation '{}' for user '{}' and provider '{}' was not committed: {}",
                            self.operation_id, self.user_id, self.provider_id, error.message
                        ),
                    )),
                    Err(read_error) => Err(ErrorResponse::new(
                        rauthy_error::ErrorResponseType::Internal,
                        format!(
                            "identity unlinked operation '{}' has an unconfirmed outcome; retain this id: write: {}; read-back: {}",
                            self.operation_id, error.message, read_error.message
                        ),
                    )),
                }
            }
        }
    }

    async fn commit_inner(&self) -> Result<(), ErrorResponse> {
        {
            let mut connection = DB::pg().await?;
            let transaction = connection.transaction().await?;
            DB::pg_txn_append(
                &transaction,
                identity_link_sql::LOCK_PERSON,
                &[&self.user_id],
            )
            .await?;
            let remaining = transaction.query_one(
                "SELECT EXISTS (SELECT 1 FROM users u WHERE u.id=$1 AND ((u.password IS NOT NULL AND (u.password_expires IS NULL OR u.password_expires>$4)) OR EXISTS (SELECT 1 FROM passkeys k WHERE k.user_id=u.id) OR EXISTS (SELECT 1 FROM identity_links l JOIN auth_providers p ON p.id=l.provider_id WHERE l.user_id=u.id AND p.enabled=TRUE AND (l.provider_id<>$2 OR l.federation_uid<>$3))))",
                &[&self.user_id, &self.provider_id, &self.subject, &self.observed_at],
            ).await?.get::<_, bool>(0);
            if !remaining {
                return Err(ErrorResponse::new(
                    rauthy_error::ErrorResponseType::BadRequest,
                    format!(
                        "identity_link_last_method: user '{}' must keep another usable sign-in method before removing provider '{}' (operation '{}')",
                        self.user_id, self.provider_id, self.operation_id
                    ),
                ));
            }
            DB::pg_txn_append(
                &transaction,
                identity_link_sql::AUDIT_UNLINK,
                &[
                    &self.operation_id,
                    &self.user_id,
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
                identity_link_sql::DELETE_LINK,
                &[&self.user_id, &self.provider_id, &self.subject],
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
