use crate::database::{DatabasePort, TransactionPort};
use crate::orm::{Direction, Filter, FindMany, Order};
use crate::private_auth::*;
use crate::server::{OperationError, Session, SessionUser};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use scrypt::{Params, scrypt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{future::Future, pin::Pin};
use subtle::ConstantTimeEq;

// Legacy refresh families become cleanup candidates once their fixed storage lifetime has passed, regardless of the session expiry value.
const LEGACY_REFRESH_LIFETIME_MILLIS: i64 = 604_800_000;

#[derive(Clone)]
pub struct AuthUser {
    pub id: String,
    pub email: String,
    pub created_at: String,
}

#[derive(serde::Serialize)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: String,
    pub refresh_expires_at: String,
    pub user_id: String,
    pub session_id: String,
}

pub struct VerifiedIdentity {
    pub subject: String,
    pub verified_email: String,
}

pub trait IdentityProvider {
    fn id(&self) -> &str;
    fn verify<'a>(
        &'a self,
        credential: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<VerifiedIdentity, OperationError>> + 'a>>;
}

#[allow(async_fn_in_trait)]
pub trait UserCreationHooks {
    async fn creating(
        &self,
        _port: TransactionPort,
        _user: &AuthUser,
    ) -> Result<(), OperationError> {
        Ok(())
    }
    async fn committed(&self, _user: &AuthUser) -> Result<(), OperationError> {
        Ok(())
    }
}

pub struct NoHooks;
impl UserCreationHooks for NoHooks {}

pub struct Auth<'a, H> {
    db: Database,
    providers: &'a [Box<dyn IdentityProvider>],
    hooks: &'a H,
    session_policy: SessionPolicy,
}

impl<'a, H: UserCreationHooks> Auth<'a, H> {
    pub fn new(
        port: DatabasePort,
        providers: &'a [Box<dyn IdentityProvider>],
        hooks: &'a H,
    ) -> Result<Self, OperationError> {
        let mut ids = std::collections::HashSet::new();
        for provider in providers {
            let id = provider.id();
            if id.is_empty()
                || id.len() > 63
                || id == "password"
                || !id.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_lowercase()
                        || index > 0 && (byte.is_ascii_digit() || byte == b'_' || byte == b'-')
                })
                || !ids.insert(id)
            {
                return Err(OperationError::new("invalid_input", 400));
            }
        }
        Ok(Self {
            db: Database::new(port),
            providers,
            hooks,
            session_policy: SessionPolicy::new(2_592_000, 0)?,
        })
    }

    pub(crate) fn with_session_policy(
        mut self,
        idle_seconds: u64,
        absolute_seconds: u64,
    ) -> Result<Self, OperationError> {
        self.session_policy = SessionPolicy::new(idle_seconds, absolute_seconds)?;
        Ok(self)
    }

    pub async fn signup(&self, email: &str, password: &str) -> Result<Tokens, OperationError> {
        let email = normalize_email(email)?;
        validate_password(password)?;
        self.rate_limit("signup", &email, 10, 900_000).await?;
        let hash = hash_password(password)?;
        let result = self
            .db
            .transaction(async |tx| {
                let user = tx
                    .app_auth_users
                    .insert(AppAuthUsersInsert {
                        email,
                        password_hash: Some(Some(hash)),
                        id: None,
                        created_at: None,
                        disabled_at: None,
                        session_version: None,
                    })
                    .await?;
                let public = public_user(&user);
                self.hooks
                    .creating(tx.port(), &public)
                    .await
                    .map_err(|_| OperationError::new("user_creation_failed", 500))?;
                Ok((self.issue(tx, &user).await?, public))
            })
            .await;
        let (tokens, user) = result.map_err(|error| {
            if error.unique_violation() {
                OperationError::new("account_exists", 409)
            } else {
                error
            }
        })?;
        self.cleanup().await;
        self.committed(&user).await?;
        Ok(tokens)
    }

    pub async fn signin(&self, email: &str, password: &str) -> Result<Tokens, OperationError> {
        let email = normalize_email(email)?;
        validate_password(password)?;
        self.rate_limit("signin", &email, 10, 900_000).await?;
        let column = self.db.app_auth_users.columns().email;
        let users = self
            .db
            .app_auth_users
            .find_many(FindMany {
                filter: Some(Filter::eq(column, json!(email))),
                limit: Some(1),
                ..Default::default()
            })
            .await?;
        let matched = verify_password(
            password,
            users.first().and_then(|user| user.password_hash.as_deref()),
        )?;
        let user = users
            .first()
            .filter(|user| matched && user.disabled_at.is_none())
            .ok_or_else(|| OperationError::new("invalid_credentials", 401))?;
        let tokens = self
            .db
            .transaction(async |tx| self.issue(tx, user).await)
            .await?;
        self.cleanup().await;
        Ok(tokens)
    }

    pub async fn signin_identity(
        &self,
        provider_id: &str,
        credential: &Value,
    ) -> Result<Tokens, OperationError> {
        let provider = self
            .providers
            .iter()
            .find(|provider| provider.id() == provider_id)
            .ok_or_else(|| OperationError::new("unsupported_identity_provider", 400))?;
        self.rate_limit("identity_attempt", provider_id, 100, 60_000)
            .await?;
        let identity = provider
            .verify(credential)
            .await
            .map_err(|_| OperationError::new("invalid_credentials", 401))?;
        let email = normalize_email(&identity.verified_email)?;
        if identity.subject.is_empty() || identity.subject.encode_utf16().count() > 2048 {
            return Err(OperationError::new("invalid_credentials", 401));
        }
        self.rate_limit(
            "identity",
            &format!("{provider_id}:{}", identity.subject),
            10,
            900_000,
        )
        .await?;
        let result = self
            .db
            .transaction(async |tx| {
                let stored = tx
                    .app_auth_identities
                    .find_by_id(AppAuthIdentitiesPrimaryKey {
                        provider: provider_id.into(),
                        subject: identity.subject.clone(),
                    })
                    .await?;
                let (user, created) = match stored {
                    Some(stored) => (
                        tx.app_auth_users
                            .find_by_id(AppAuthUsersPrimaryKey { id: stored.user_id })
                            .await?
                            .ok_or_else(|| OperationError::new("invalid_credentials", 401))?,
                        false,
                    ),
                    None => {
                        let user = tx
                            .app_auth_users
                            .insert(AppAuthUsersInsert {
                                email,
                                password_hash: Some(None),
                                id: None,
                                created_at: None,
                                disabled_at: None,
                                session_version: None,
                            })
                            .await?;
                        tx.app_auth_identities
                            .insert(AppAuthIdentitiesInsert {
                                provider: provider_id.into(),
                                subject: identity.subject.clone(),
                                user_id: user.id.clone(),
                                created_at: None,
                            })
                            .await?;
                        (user, true)
                    }
                };
                if user.disabled_at.is_some() {
                    return Err(OperationError::new("invalid_credentials", 401));
                }
                let public = public_user(&user);
                if created {
                    self.hooks
                        .creating(tx.port(), &public)
                        .await
                        .map_err(|_| OperationError::new("user_creation_failed", 500))?;
                }
                Ok((self.issue(tx, &user).await?, created.then_some(public)))
            })
            .await
            .map_err(|error| {
                if error.unique_violation() {
                    OperationError::new("identity_conflict", 409)
                } else {
                    error
                }
            })?;
        self.cleanup().await;
        if let Some(user) = result.1 {
            self.committed(&user).await?;
        }
        Ok(result.0)
    }

    async fn committed(&self, user: &AuthUser) -> Result<(), OperationError> {
        self.hooks
            .committed(user)
            .await
            .map_err(|_| OperationError::new("user_created_effect_failed", 500))
    }

    pub async fn session(&self, token: &str) -> Result<Session, OperationError> {
        validate_token(token)?;
        let rows = self
            .db
            .app_auth_sessions
            .find_many(FindMany {
                filter: Some(Filter::eq(
                    self.db.app_auth_sessions.columns().token_hash,
                    json!(token_digest(token)),
                )),
                limit: Some(1),
                ..Default::default()
            })
            .await?;
        let stored = rows.first().ok_or_else(OperationError::invalid_token)?;
        let outcome = self
            .db
            .transaction(async |tx| {
                let columns = tx.app_auth_sessions.columns();
                let session = tx
                    .app_auth_sessions
                    .update_if(
                        AppAuthSessionsPrimaryKey {
                            id: stored.id.clone(),
                        },
                        Filter::all(vec![
                            Filter::is_null(columns.revoked_at),
                            Filter::eq(columns.token_hash, json!(token_digest(token))),
                            Filter::eq(columns.transport, json!("native")),
                        ]),
                        AppAuthSessionsUpdate {
                            revoked_at: Some(None),
                            ..Default::default()
                        },
                    )
                    .await?;
                let Some(session) = session else {
                    return Ok(None);
                };
                let latest_refresh = tx
                    .app_auth_refresh_tokens
                    .find_many(FindMany {
                        filter: Some(Filter::all(vec![
                            Filter::eq(
                                tx.app_auth_refresh_tokens.columns().session_id,
                                json!(session.id),
                            ),
                            Filter::is_null(tx.app_auth_refresh_tokens.columns().consumed_at),
                        ])),
                        order: vec![Order {
                            column: tx.app_auth_refresh_tokens.columns().created_at,
                            direction: Direction::Descending,
                        }],
                        limit: Some(1),
                        ..Default::default()
                    })
                    .await?
                    .into_iter()
                    .next();
                let user = tx
                    .app_auth_users
                    .find_by_id(AppAuthUsersPrimaryKey {
                        id: session.user_id.clone(),
                    })
                    .await?;
                let now = now_millis();
                if (session.first_login_at.is_some() && latest_refresh.is_none())
                    || self.session_policy.expired(
                        now,
                        session.first_login_at.as_deref(),
                        &session.created_at,
                        session.last_renewed_at.as_deref(),
                        latest_refresh.as_ref().map(|row| row.created_at.as_str()),
                        latest_refresh.as_ref().map(|row| row.expires_at.as_str()),
                    )?
                {
                    tx.app_auth_sessions
                        .update(
                            AppAuthSessionsPrimaryKey { id: session.id },
                            AppAuthSessionsUpdate {
                                revoked_at: Some(Some(timestamp_at(now)?)),
                                ..Default::default()
                            },
                        )
                        .await?;
                    return Ok(None);
                }
                if now >= parse_timestamp(&session.expires_at)? {
                    return Ok(None);
                }
                let Some(user) = user.filter(|user| {
                    user.disabled_at.is_none()
                        && user.session_version == session.user_session_version
                }) else {
                    return Ok(None);
                };
                Ok(Some(Session {
                    id: session.id,
                    user: SessionUser {
                        id: user.id,
                        email: user.email,
                    },
                }))
            })
            .await?;
        outcome.ok_or_else(OperationError::invalid_token)
    }

    pub async fn logout(&self, token: &str) -> Result<(), OperationError> {
        let session = self.session(token).await?;
        self.db
            .app_auth_sessions
            .update_if(
                AppAuthSessionsPrimaryKey { id: session.id },
                Filter::is_null(self.db.app_auth_sessions.columns().revoked_at),
                AppAuthSessionsUpdate {
                    revoked_at: Some(Some(timestamp(0)?)),
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }

    pub async fn refresh(&self, token: &str) -> Result<Tokens, OperationError> {
        validate_token(token)?;
        let rows = self
            .db
            .app_auth_refresh_tokens
            .find_many(FindMany {
                filter: Some(Filter::eq(
                    self.db.app_auth_refresh_tokens.columns().token_hash,
                    json!(token_digest(token)),
                )),
                limit: Some(1),
                ..Default::default()
            })
            .await?;
        let stored = rows.first().ok_or_else(OperationError::invalid_token)?;
        let outcome = self
            .db
            .transaction(async |tx| {
                let session = tx
                    .app_auth_sessions
                    .update_if(
                        AppAuthSessionsPrimaryKey {
                            id: stored.session_id.clone(),
                        },
                        Filter::all(vec![
                            Filter::is_null(tx.app_auth_sessions.columns().revoked_at),
                            Filter::eq(tx.app_auth_sessions.columns().transport, json!("native")),
                        ]),
                        AppAuthSessionsUpdate {
                            revoked_at: Some(None),
                            ..Default::default()
                        },
                    )
                    .await?;
                let Some(session) = session else {
                    return Ok(None);
                };
                let current = tx
                    .app_auth_refresh_tokens
                    .find_by_id(AppAuthRefreshTokensPrimaryKey {
                        id: stored.id.clone(),
                    })
                    .await?;
                let user = tx
                    .app_auth_users
                    .find_by_id(AppAuthUsersPrimaryKey {
                        id: session.user_id.clone(),
                    })
                    .await?;
                let now = now_millis();
                let valid = match (&current, &user) {
                    (Some(current), Some(user)) => {
                        current.consumed_at.is_none()
                            && !self.session_policy.expired(
                                now,
                                session.first_login_at.as_deref(),
                                &session.created_at,
                                session.last_renewed_at.as_deref(),
                                Some(&current.created_at),
                                Some(&current.expires_at),
                            )?
                            && user.disabled_at.is_none()
                            && user.session_version == session.user_session_version
                    }
                    _ => false,
                };
                if !valid {
                    tx.app_auth_sessions
                        .update(
                            AppAuthSessionsPrimaryKey { id: session.id },
                            AppAuthSessionsUpdate {
                                revoked_at: Some(Some(timestamp_at(now)?)),
                                ..Default::default()
                            },
                        )
                        .await?;
                    return Ok(None);
                }
                let current = current.ok_or_else(OperationError::internal)?;
                let consumed = tx
                    .app_auth_refresh_tokens
                    .update_if(
                        AppAuthRefreshTokensPrimaryKey { id: current.id },
                        Filter::is_null(tx.app_auth_refresh_tokens.columns().consumed_at),
                        AppAuthRefreshTokensUpdate {
                            consumed_at: Some(Some(timestamp_at(now)?)),
                            ..Default::default()
                        },
                    )
                    .await?;
                if consumed.is_none() {
                    tx.app_auth_sessions
                        .update(
                            AppAuthSessionsPrimaryKey { id: session.id },
                            AppAuthSessionsUpdate {
                                revoked_at: Some(Some(timestamp_at(now)?)),
                                ..Default::default()
                            },
                        )
                        .await?;
                    return Ok(None);
                }
                let access_token = random_token()?;
                let refresh_token = random_token()?;
                let expires_at = timestamp_at(now + 900_000)?;
                let refresh_expires_at = timestamp_at(
                    self.session_policy.expires_at(
                        parse_timestamp(
                            session
                                .first_login_at
                                .as_deref()
                                .unwrap_or(&session.created_at),
                        )?,
                        now,
                    ),
                )?;
                tx.app_auth_sessions
                    .update(
                        AppAuthSessionsPrimaryKey {
                            id: session.id.clone(),
                        },
                        AppAuthSessionsUpdate {
                            token_hash: Some(token_digest(&access_token)),
                            expires_at: Some(expires_at.clone()),
                            first_login_at: Some(Some(
                                session.first_login_at.clone().unwrap_or(session.created_at),
                            )),
                            last_renewed_at: Some(Some(timestamp_at(now)?)),
                            ..Default::default()
                        },
                    )
                    .await?;
                tx.app_auth_refresh_tokens
                    .insert(AppAuthRefreshTokensInsert {
                        session_id: session.id.clone(),
                        token_hash: token_digest(&refresh_token),
                        expires_at: refresh_expires_at.clone(),
                        consumed_at: None,
                        created_at: Some(timestamp_at(now)?),
                        id: None,
                    })
                    .await?;
                Ok(Some(Tokens {
                    access_token,
                    refresh_token,
                    expires_at,
                    refresh_expires_at,
                    user_id: session.user_id,
                    session_id: session.id,
                }))
            })
            .await?;
        let tokens = outcome.ok_or_else(|| OperationError::new("session_revoked", 401))?;
        self.cleanup().await;
        Ok(tokens)
    }

    async fn issue(
        &self,
        tx: &TransactionDatabase,
        user: &AppAuthUsersRow,
    ) -> Result<Tokens, OperationError> {
        let access_token = random_token()?;
        let refresh_token = random_token()?;
        let now = now_millis();
        let expires_at = timestamp_at(now + 900_000)?;
        let refresh_expires_at = timestamp_at(self.session_policy.expires_at(now, now))?;
        let session = tx
            .app_auth_sessions
            .insert(AppAuthSessionsInsert {
                user_id: user.id.clone(),
                token_hash: token_digest(&access_token),
                user_session_version: user.session_version,
                expires_at: expires_at.clone(),
                revoked_at: None,
                id: None,
                created_at: Some(timestamp_at(now)?),
                first_login_at: Some(Some(timestamp_at(now)?)),
                last_renewed_at: Some(Some(timestamp_at(now)?)),
                transport: None,
            })
            .await?;
        tx.app_auth_refresh_tokens
            .insert(AppAuthRefreshTokensInsert {
                session_id: session.id.clone(),
                token_hash: token_digest(&refresh_token),
                expires_at: refresh_expires_at.clone(),
                consumed_at: None,
                created_at: Some(timestamp_at(now)?),
                id: None,
            })
            .await?;
        Ok(Tokens {
            access_token,
            refresh_token,
            expires_at,
            refresh_expires_at,
            user_id: user.id.clone(),
            session_id: session.id,
        })
    }

    async fn cleanup(&self) {
        // Cleanup runs after issuance commits so maintenance cannot undo issued credentials.
        let _ = self
            .db
            .transaction(async |tx| {
                let mut remaining = 96;
                let now = now_millis();
                let candidates = tx
                    .app_auth_sessions
                    .find_many(FindMany {
                        filter: Some(self.cleanup_candidates(tx, now)?),
                        limit: Some(remaining),
                        ..Default::default()
                    })
                    .await?;
                for candidate in candidates {
                    let session = tx
                        .app_auth_sessions
                        .update_if(
                            AppAuthSessionsPrimaryKey { id: candidate.id },
                            self.cleanup_candidates(tx, now)?,
                            AppAuthSessionsUpdate {
                                created_at: Some(candidate.created_at),
                                ..Default::default()
                            },
                        )
                        .await?;
                    let Some(session) = session else { continue };
                    if session.revoked_at.is_none() {
                        let latest = tx
                            .app_auth_refresh_tokens
                            .find_many(FindMany {
                                filter: Some(Filter::all(vec![
                                    Filter::eq(
                                        tx.app_auth_refresh_tokens.columns().session_id,
                                        json!(session.id),
                                    ),
                                    Filter::is_null(
                                        tx.app_auth_refresh_tokens.columns().consumed_at,
                                    ),
                                ])),
                                order: vec![Order {
                                    column: tx.app_auth_refresh_tokens.columns().created_at,
                                    direction: Direction::Descending,
                                }],
                                limit: Some(1),
                                ..Default::default()
                            })
                            .await?
                            .into_iter()
                            .next();
                        if !(session.first_login_at.is_none() && latest.is_none())
                            && !self.session_policy.expired(
                                now,
                                session.first_login_at.as_deref(),
                                &session.created_at,
                                session.last_renewed_at.as_deref(),
                                latest.as_ref().map(|row| row.created_at.as_str()),
                                latest.as_ref().map(|row| row.expires_at.as_str()),
                            )?
                        {
                            continue;
                        }
                        tx.app_auth_sessions
                            .update(
                                AppAuthSessionsPrimaryKey {
                                    id: session.id.clone(),
                                },
                                AppAuthSessionsUpdate {
                                    revoked_at: Some(Some(timestamp_at(now)?)),
                                    ..Default::default()
                                },
                            )
                            .await?;
                    }
                    let refreshes = tx
                        .app_auth_refresh_tokens
                        .find_many(FindMany {
                            filter: Some(Filter::eq(
                                tx.app_auth_refresh_tokens.columns().session_id,
                                json!(session.id),
                            )),
                            limit: Some(remaining),
                            ..Default::default()
                        })
                        .await?;
                    for refresh in refreshes {
                        tx.app_auth_refresh_tokens
                            .delete(AppAuthRefreshTokensPrimaryKey { id: refresh.id })
                            .await?;
                        remaining -= 1;
                    }
                    if remaining == 0 {
                        break;
                    }
                    tx.app_auth_sessions
                        .delete(AppAuthSessionsPrimaryKey { id: session.id })
                        .await?;
                    remaining -= 1;
                    if remaining == 0 {
                        break;
                    }
                }
                if remaining > 0 {
                    let columns = tx.app_auth_rate_limits.columns();
                    let elapsed = Filter::le(columns.expires_at, json!(timestamp_at(now)?));
                    let limits = tx
                        .app_auth_rate_limits
                        .find_many(FindMany {
                            filter: Some(elapsed.clone()),
                            limit: Some(remaining),
                            ..Default::default()
                        })
                        .await?;
                    for limit in limits {
                        let key = AppAuthRateLimitsPrimaryKey {
                            action: limit.action,
                            key_hash: limit.key_hash,
                        };
                        if tx
                            .app_auth_rate_limits
                            .update_if(
                                AppAuthRateLimitsPrimaryKey {
                                    action: key.action.clone(),
                                    key_hash: key.key_hash.clone(),
                                },
                                elapsed.clone(),
                                AppAuthRateLimitsUpdate {
                                    expires_at: Some(limit.expires_at),
                                    ..Default::default()
                                },
                            )
                            .await?
                            .is_some()
                        {
                            tx.app_auth_rate_limits.delete(key).await?;
                        }
                    }
                }
                Ok(())
            })
            .await;
    }

    fn cleanup_candidates(
        &self,
        tx: &TransactionDatabase,
        now: i64,
    ) -> Result<Filter, OperationError> {
        let columns = tx.app_auth_sessions.columns();
        let cutoff = json!(timestamp_at(now - self.session_policy.idle_millis)?);
        let mut filters = vec![
            Filter::is_not_null(columns.revoked_at),
            Filter::le(columns.last_renewed_at, cutoff.clone()),
            Filter::all(vec![
                Filter::is_null(columns.last_renewed_at),
                Filter::le(columns.expires_at, cutoff),
            ]),
            Filter::all(vec![
                Filter::is_null(columns.last_renewed_at),
                Filter::le(
                    columns.created_at,
                    json!(timestamp_at(now - LEGACY_REFRESH_LIFETIME_MILLIS)?),
                ),
            ]),
        ];
        if self.session_policy.absolute_millis != 0 {
            let cutoff = json!(timestamp_at(now - self.session_policy.absolute_millis)?);
            filters.push(Filter::le(columns.first_login_at, cutoff.clone()));
            filters.push(Filter::all(vec![
                Filter::is_null(columns.first_login_at),
                Filter::le(columns.created_at, cutoff),
            ]));
        }
        Ok(Filter::all(vec![
            Filter::eq(columns.transport, json!("native")),
            Filter::any(filters),
        ]))
    }

    async fn rate_limit(
        &self,
        action: &str,
        value: &str,
        maximum: i32,
        window: i64,
    ) -> Result<(), OperationError> {
        let hash = token_digest(value);
        for _ in 0..4 {
            let row = self
                .db
                .app_auth_rate_limits
                .find_by_id(AppAuthRateLimitsPrimaryKey {
                    action: action.into(),
                    key_hash: hash.clone(),
                })
                .await?;
            let Some(row) = row else {
                match self
                    .db
                    .app_auth_rate_limits
                    .insert(AppAuthRateLimitsInsert {
                        action: action.into(),
                        key_hash: hash.clone(),
                        attempt_count: 1,
                        expires_at: timestamp(window)?,
                    })
                    .await
                {
                    Ok(_) => return Ok(()),
                    Err(error) if error.unique_violation() => continue,
                    Err(error) => return Err(error),
                }
            };
            let elapsed = expired(&row.expires_at)?;
            if !elapsed && row.attempt_count >= maximum {
                return Err(OperationError::new("rate_limited", 429));
            }
            let columns = self.db.app_auth_rate_limits.columns();
            if self
                .db
                .app_auth_rate_limits
                .update_if(
                    AppAuthRateLimitsPrimaryKey {
                        action: action.into(),
                        key_hash: hash.clone(),
                    },
                    Filter::all(vec![
                        Filter::eq(columns.attempt_count, json!(row.attempt_count)),
                        Filter::eq(columns.expires_at, json!(row.expires_at)),
                    ]),
                    AppAuthRateLimitsUpdate {
                        attempt_count: Some(if elapsed { 1 } else { row.attempt_count + 1 }),
                        expires_at: Some(if elapsed {
                            timestamp(window)?
                        } else {
                            row.expires_at
                        }),
                    },
                )
                .await?
                .is_some()
            {
                return Ok(());
            }
        }
        Err(OperationError::new("rate_limited", 429))
    }
}

fn public_user(row: &AppAuthUsersRow) -> AuthUser {
    AuthUser {
        id: row.id.clone(),
        email: row.email.clone(),
        created_at: row.created_at.clone(),
    }
}

fn normalize_email(value: &str) -> Result<String, OperationError> {
    // ECMAScript WhiteSpace and LineTerminator exclude NEL (U+0085).
    let is_whitespace = |ch| {
        matches!(
            ch,
            '\u{0009}'..='\u{000d}'
                | '\u{0020}'
                | '\u{00a0}'
                | '\u{1680}'
                | '\u{2000}'..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
        )
    };
    let email = value.trim_matches(is_whitespace).to_lowercase();
    if email.contains('\0') {
        return Err(OperationError::new("invalid_input", 400));
    }
    let parts: Vec<_> = email.split('@').collect();
    // Both sides of the JS pattern's domain separator also allow dots.
    let valid_domain = parts.get(1).is_some_and(|domain| {
        domain
            .match_indices('.')
            .any(|(index, _)| index > 0 && index + 1 < domain.len())
    });
    if parts.len() != 2
        || parts[0].is_empty()
        || !valid_domain
        || email.chars().any(is_whitespace)
        || email.encode_utf16().count() > 320
    {
        return Err(OperationError::new("invalid_input", 400));
    }
    Ok(email)
}

fn validate_password(password: &str) -> Result<(), OperationError> {
    if password.chars().count() < 15 || password.len() > 1024 {
        return Err(OperationError::new("invalid_input", 400));
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<(), OperationError> {
    if token.len() != 43
        || !token
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-')
    {
        return Err(OperationError::invalid_token());
    }
    Ok(())
}

struct SessionPolicy {
    idle_millis: i64,
    absolute_millis: i64,
}

impl SessionPolicy {
    fn new(idle_seconds: u64, absolute_seconds: u64) -> Result<Self, OperationError> {
        if !(3_600..=31_536_000).contains(&idle_seconds)
            || absolute_seconds != 0 && !(3_600..=31_536_000).contains(&absolute_seconds)
        {
            return Err(OperationError::new("invalid_session_policy", 500));
        }
        Ok(Self {
            idle_millis: idle_seconds as i64 * 1_000,
            absolute_millis: absolute_seconds as i64 * 1_000,
        })
    }

    fn expires_at(&self, first_login: i64, last_rotation: i64) -> i64 {
        let idle = last_rotation.saturating_add(self.idle_millis);
        if self.absolute_millis == 0 {
            idle
        } else {
            idle.min(first_login.saturating_add(self.absolute_millis))
        }
    }

    fn expired(
        &self,
        now: i64,
        first_login_at: Option<&str>,
        family_created_at: &str,
        last_renewed_at: Option<&str>,
        latest_refresh_created_at: Option<&str>,
        stored_expires_at: Option<&str>,
    ) -> Result<bool, OperationError> {
        if (stored_expires_at.is_some() || first_login_at.is_none())
            && now >= parse_timestamp(stored_expires_at.ok_or_else(OperationError::internal)?)?
        {
            return Ok(true);
        }
        let first_login = parse_timestamp(first_login_at.unwrap_or(family_created_at))?;
        let last_renewed = if first_login_at.is_none() {
            parse_timestamp(latest_refresh_created_at.ok_or_else(OperationError::internal)?)?
        } else {
            last_renewed_at
                .map(parse_timestamp)
                .transpose()?
                .unwrap_or(first_login)
        };
        Ok(now >= self.expires_at(first_login, last_renewed))
    }
}

fn now_millis() -> i64 {
    #[cfg(all(test, not(target_arch = "wasm32")))]
    {
        crate::host::testing::NOW
    }
    #[cfg(not(all(test, not(target_arch = "wasm32"))))]
    {
        js_sys::Date::now() as i64
    }
}

fn timestamp(delta: i64) -> Result<String, OperationError> {
    timestamp_at(now_millis() + delta)
}

fn timestamp_at(millis: i64) -> Result<String, OperationError> {
    DateTime::<Utc>::from_timestamp_millis(millis)
        .map(|date| date.to_rfc3339_opts(SecondsFormat::Millis, true))
        .ok_or_else(OperationError::internal)
}

fn expired(value: &str) -> Result<bool, OperationError> {
    Ok(parse_timestamp(value)? <= now_millis())
}

fn parse_timestamp(value: &str) -> Result<i64, OperationError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .or_else(|_| DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f%#z"))
        .map_err(|_| OperationError::internal())?;
    Ok(parsed.timestamp_millis())
}

fn hash_password(password: &str) -> Result<String, OperationError> {
    let salt = crate::host::random_bytes(16).map_err(|_| OperationError::internal())?;
    let key = derive(password, &salt)?;
    let salt = hex::encode(salt);
    let hash = hex::encode(key);
    Ok(format!("scrypt$32768$8$3${salt}${hash}"))
}

fn verify_password(password: &str, stored: Option<&str>) -> Result<bool, OperationError> {
    let parts: Vec<_> = stored.unwrap_or("").split('$').collect();
    let valid = parts.len() == 6
        && parts[..4] == ["scrypt", "32768", "8", "3"]
        && parts[4].len() == 32
        && parts[5].len() == 64
        && parts[4..].iter().all(|part| {
            part.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    let (salt, expected) = if valid {
        (
            hex::decode(parts[4]).map_err(|_| OperationError::internal())?,
            hex::decode(parts[5]).map_err(|_| OperationError::internal())?,
        )
    } else {
        (vec![0; 16], vec![0; 32])
    };
    let actual = derive(password, &salt)?;
    let matched = bool::from(actual.as_slice().ct_eq(expected.as_slice()));
    Ok(valid && matched)
}

fn derive(password: &str, salt: &[u8]) -> Result<[u8; 32], OperationError> {
    let mut key = [0; 32];
    let params = Params::new(15, 8, 3, 32).map_err(|_| OperationError::internal())?;
    scrypt(password.as_bytes(), salt, &params, &mut key).map_err(|_| OperationError::internal())?;
    Ok(key)
}

fn random_token() -> Result<String, OperationError> {
    crate::host::random_bytes(32)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|_| OperationError::internal())
}

fn token_digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400_000;

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn shared_email_normalization_corpus() {
        #[derive(serde::Deserialize)]
        struct Case {
            name: String,
            input: String,
            normalized: Option<String>,
            error: Option<String>,
        }

        let corpus = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/emails.json"
        ))
        .expect("shared email corpus must be readable");
        let cases: Vec<Case> =
            serde_json::from_str(&corpus).expect("shared email corpus must be valid JSON");
        assert!(
            !cases.is_empty(),
            "0 cases, 1 failures: shared email corpus must not be empty"
        );

        let mut failures = Vec::new();
        let count = cases.len();
        for case in cases {
            let expected = match (case.normalized, case.error) {
                (Some(normalized), None) => Ok(normalized),
                (None, Some(error)) => {
                    assert_eq!(error, "invalid_input", "{}: unknown error", case.name);
                    Err(error)
                }
                _ => panic!("{}: expected exactly one outcome", case.name),
            };
            if normalize_email(&case.input).map_err(|error| error.code) != expected {
                failures.push(case.name);
            }
        }
        println!("{count} cases, {} failures", failures.len());
        assert!(
            failures.is_empty(),
            "failing cases: {}",
            failures.join(", ")
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod rolling {
        use super::*;
        use crate::host::testing;
        use std::{cell::RefCell, collections::VecDeque, rc::Rc};

        const SESSION_ID: &str = "00000000-0000-4000-8000-000000000001";
        const USER_ID: &str = "00000000-0000-4000-8000-000000000002";
        const REFRESH_ID: &str = "00000000-0000-4000-8000-000000000003";

        fn session() -> Value {
            json!({
                "id": SESSION_ID, "user_id": USER_ID, "user_session_version": 1,
                "created_at": checked(timestamp_at(testing::NOW - 10 * DAY)),
                "first_login_at": checked(timestamp_at(testing::NOW - 10 * DAY)),
                "last_renewed_at": checked(timestamp_at(testing::NOW - 600_000)),
                "expires_at": checked(timestamp_at(testing::NOW + 900_000)),
                "revoked_at": null, "token_hash": "", "transport": "native"
            })
        }

        fn refresh() -> Value {
            json!({
                "id": REFRESH_ID, "session_id": SESSION_ID, "token_hash": "",
                "created_at": checked(timestamp_at(testing::NOW - 600_000)),
                "expires_at": checked(timestamp_at(testing::NOW + DAY)),
                "consumed_at": null
            })
        }

        fn user() -> Value {
            json!({
                "id": USER_ID, "email": "user@example.test", "session_version": 1,
                "created_at": checked(timestamp_at(0)),
                "disabled_at": null, "password_hash": null
            })
        }

        fn rows(row: Value) -> Value {
            json!({"rows": [row]})
        }

        fn run<T>(
            script: Vec<(&'static str, Value)>,
            future: impl Future<Output = T>,
        ) -> (T, Vec<Value>) {
            let calls = Rc::new(RefCell::new(Vec::new()));
            let recorded = calls.clone();
            let mut responses: VecDeque<_> = script.into();
            let result = testing::run(
                move |request| {
                    let (op, response) = responses.pop_front().expect("unexpected host call");
                    assert!(request["op"] == op, "unexpected transaction operation");
                    assert!(request["rid"] == 1, "request changed database connection");
                    if op == "exec" || op == "commit" {
                        assert!(request["lease"] == 7, "transaction changed database lease");
                    }
                    // An expiry predicate would hide a consumed credential before reuse detection.
                    let hides_expired = op == "query"
                        && request["sql"]
                            .as_str()
                            .unwrap()
                            .split(" where ")
                            .nth(1)
                            .is_some_and(|filter| filter.contains("\"expires_at\""));
                    recorded.borrow_mut().push(request);
                    if hides_expired {
                        json!({"rows": []})
                    } else {
                        response
                    }
                },
                future,
            );
            let calls = calls.take();
            (result, calls)
        }

        fn assignment<'a>(request: &'a Value, column: &str) -> Option<&'a Value> {
            let sql = request["sql"].as_str()?;
            let assignments = sql.split_once(" set ")?.1.split_once(" where ")?.0;
            for term in assignments.split(", ") {
                let (name, index) = term.split_once(" = $").unwrap();
                if name.trim_matches('"') == column {
                    return request["params"].get(index.parse::<usize>().unwrap() - 1);
                }
            }
            None
        }

        fn assert_revoked_and_committed(calls: &[Value]) {
            let revocation = &calls[calls.len() - 2];
            assert!(
                revocation["sql"]
                    .as_str()
                    .unwrap()
                    .starts_with("update \"app_auth_sessions\"")
            );
            assert!(
                assignment(revocation, "revoked_at")
                    == Some(&json!(checked(timestamp_at(testing::NOW))))
            );
            assert!(
                calls.last().unwrap()["op"] == "commit",
                "revocation was not committed"
            );
            assert!(
                calls
                    .iter()
                    .all(|call| assignment(call, "first_login_at").is_none()
                        && assignment(call, "last_renewed_at").is_none()
                        && assignment(call, "expires_at").is_none())
            );
        }

        #[derive(Default)]
        struct CleanupHost {
            tables: std::collections::BTreeMap<String, Vec<Value>>,
            calls: Vec<Value>,
            deleted: usize,
        }

        fn matches_filter(expression: &str, params: &[Value], row: &Value) -> bool {
            fn evaluate(tokens: &[&str], params: &[Value], row: &Value) -> bool {
                let mut depth = 0;
                for (index, token) in tokens.iter().enumerate() {
                    match *token {
                        "(" => depth += 1,
                        ")" => depth -= 1,
                        _ => {}
                    }
                    if depth == 0 && (*token == "or" || *token == "and") {
                        let left = evaluate(&tokens[..index], params, row);
                        let right = evaluate(&tokens[index + 1..], params, row);
                        return if *token == "or" {
                            left || right
                        } else {
                            left && right
                        };
                    }
                }
                if tokens[0] == "not" {
                    return !evaluate(&tokens[1..], params, row);
                }
                if tokens[0] == "(" {
                    return evaluate(&tokens[1..tokens.len() - 1], params, row);
                }
                let value = &row[tokens[0].trim_matches('"')];
                if tokens[1] == "is" {
                    return value.is_null() == (tokens[2] == "null");
                }
                let bound =
                    &params[tokens[2].trim_start_matches('$').parse::<usize>().unwrap() - 1];
                if value.is_null() || bound.is_null() {
                    return false;
                }
                let ordering = match (value.as_str(), bound.as_str()) {
                    (Some(left), Some(right)) => {
                        match (parse_timestamp(left), parse_timestamp(right)) {
                            (Ok(left), Ok(right)) => left.cmp(&right),
                            _ => left.cmp(right),
                        }
                    }
                    _ => value.as_i64().unwrap().cmp(&bound.as_i64().unwrap()),
                };
                match tokens[1] {
                    "=" => ordering.is_eq(),
                    "<=" => !ordering.is_gt(),
                    "<" => ordering.is_lt(),
                    ">" => ordering.is_gt(),
                    ">=" => !ordering.is_lt(),
                    _ => panic!("unsupported predicate"),
                }
            }
            let spaced = expression.replace('(', " ( ").replace(')', " ) ");
            evaluate(&spaced.split_whitespace().collect::<Vec<_>>(), params, row)
        }

        impl CleanupHost {
            fn add(&mut self, table: &str, row: Value) {
                self.tables.entry(table.into()).or_default().push(row);
            }

            fn respond(&mut self, request: Value) -> Value {
                self.calls.push(request.clone());
                let op = request["op"].as_str().unwrap();
                if op == "begin" {
                    return json!({"lease": 7});
                }
                if op == "commit" || op == "rollback" {
                    return json!({});
                }
                let sql = request["sql"].as_str().unwrap();
                let params = request["params"].as_array().unwrap();
                let table = sql
                    .split('"')
                    .find(|word| word.starts_with("app_auth_"))
                    .unwrap();
                let rows = self.tables.entry(table.into()).or_default();
                if sql.starts_with("insert ") {
                    let columns = sql.split_once('(').unwrap().1.split_once(')').unwrap().0;
                    let mut row =
                        json!({"id": fixture_id(10_000 + rows.len()), "consumed_at": null});
                    for (column, value) in columns.split(", ").zip(params) {
                        row[column.trim_matches('"')] = value.clone();
                    }
                    rows.push(row.clone());
                    return json!({"rows": [row]});
                }
                let filter = sql.split_once(" where ").map(|(_, tail)| {
                    tail.split(" order by ")
                        .next()
                        .unwrap()
                        .split(" limit ")
                        .next()
                        .unwrap()
                        .split(" returning ")
                        .next()
                        .unwrap()
                });
                let mut selected: Vec<_> = rows
                    .iter()
                    .enumerate()
                    .filter(|(_, row)| {
                        filter.is_none_or(|filter| matches_filter(filter, params, row))
                    })
                    .map(|(index, _)| index)
                    .collect();
                if let Some((_, order)) = sql.split_once(" order by ") {
                    let column = order.split('"').nth(1).unwrap();
                    selected.sort_by_key(|index| rows[*index][column].as_str().unwrap().to_owned());
                    if order.contains(" desc") {
                        selected.reverse();
                    }
                }
                if let Some((_, limit)) = sql.split_once(" limit ") {
                    let limit = limit.split_whitespace().next().unwrap();
                    let count = if let Some(index) = limit.strip_prefix('$') {
                        params[index.parse::<usize>().unwrap() - 1]
                            .as_u64()
                            .unwrap() as usize
                    } else {
                        limit.parse().unwrap()
                    };
                    selected.truncate(count);
                }
                if sql.starts_with("update ") {
                    let set = sql
                        .split_once(" set ")
                        .unwrap()
                        .1
                        .split_once(" where ")
                        .unwrap()
                        .0;
                    for &index in &selected {
                        for term in set.split(", ") {
                            let (column, parameter) = term.split_once(" = $").unwrap();
                            rows[index][column.trim_matches('"')] =
                                params[parameter.parse::<usize>().unwrap() - 1].clone();
                        }
                    }
                }
                let result: Vec<_> = selected.iter().map(|index| rows[*index].clone()).collect();
                if sql.starts_with("delete ") {
                    self.deleted += selected.len();
                    selected.sort_unstable();
                    for index in selected.into_iter().rev() {
                        rows.remove(index);
                    }
                }
                json!({"rows": result})
            }
        }

        fn fixture_id(index: usize) -> String {
            format!("00000000-0000-4000-8000-{index:012}")
        }

        #[test]
        fn f05_cleanup_budget_and_progress_preserve_reuse_revocation() {
            let auth = checked(Auth::new(DatabasePort::new(1), &[], &NoHooks));
            let mut host = CleanupHost::default();
            let mut live = session();
            live["token_hash"] = json!(token_digest(&"B".repeat(43)));
            live["first_login_at"] = json!(checked(timestamp_at(0)));
            live["created_at"] = live["first_login_at"].clone();
            host.add("app_auth_sessions", live.clone());
            for index in 0..100 {
                let mut old = refresh();
                old["id"] = json!(fixture_id(index + 100));
                old["token_hash"] = json!(token_digest(&if index == 0 {
                    "A".repeat(43)
                } else {
                    format!("old-{index}")
                }));
                old["created_at"] = json!(checked(timestamp_at(0)));
                old["expires_at"] = json!(checked(timestamp_at(30 * DAY)));
                old["consumed_at"] = json!(checked(timestamp_at(29 * DAY)));
                host.add("app_auth_refresh_tokens", old);
            }
            let mut latest = refresh();
            latest["id"] = json!(fixture_id(450));
            latest["token_hash"] = json!(token_digest(&"C".repeat(43)));
            host.add("app_auth_refresh_tokens", latest);
            let mut dead = session();
            dead["id"] = json!(fixture_id(500));
            dead["created_at"] = json!(checked(timestamp_at(testing::NOW - 8 * DAY)));
            dead["first_login_at"] = Value::Null;
            dead["last_renewed_at"] = Value::Null;
            host.add("app_auth_sessions", dead.clone());
            for index in 0..110 {
                let mut old = refresh();
                old["id"] = json!(fixture_id(index + 600));
                old["session_id"] = dead["id"].clone();
                old["token_hash"] = json!(token_digest(&format!("dead-{index}")));
                old["created_at"] = dead["created_at"].clone();
                old["expires_at"] = json!(checked(timestamp_at(testing::NOW - DAY)));
                host.add("app_auth_refresh_tokens", old);
            }
            for index in 0..110 {
                host.add("app_auth_rate_limits", json!({"action": "signin", "key_hash": format!("{index:064x}"), "attempt_count": 10, "expires_at": checked(timestamp_at(testing::NOW))}));
            }
            host.add("app_auth_users", user());
            let state = Rc::new(RefCell::new(host));
            for pass in 0..4 {
                let state_host = state.clone();
                let before = state.borrow().deleted;
                testing::run(
                    move |request| state_host.borrow_mut().respond(request),
                    auth.cleanup(),
                );
                let after = state.borrow().deleted;
                assert!(after - before <= 96, "cleanup exceeded deletion budget");
                if pass == 0 {
                    assert_eq!(
                        after - before,
                        96,
                        "cleanup made no progress past retained credentials"
                    );
                }
            }
            {
                let host = state.borrow();
                assert_eq!(
                    host.tables["app_auth_sessions"].len(),
                    1,
                    "dead family was not removed"
                );
                assert!(host.tables["app_auth_rate_limits"].is_empty());
                assert_eq!(
                    host.tables["app_auth_sessions"][0]["revoked_at"],
                    Value::Null
                );
            }
            let state_host = state.clone();
            let error = testing::run(
                move |request| state_host.borrow_mut().respond(request),
                auth.refresh(&"A".repeat(43)),
            )
            .err()
            .expect("reuse accepted");
            assert_eq!(
                error.code, "session_revoked",
                "cleanup hid retained reuse credential"
            );
            let state_host = state.clone();
            let error = testing::run(
                move |request| state_host.borrow_mut().respond(request),
                auth.session(&"B".repeat(43)),
            )
            .err()
            .expect("revoked access accepted");
            assert_eq!(error.code, "invalid_token");
            let state_host = state.clone();
            let error = testing::run(
                move |request| state_host.borrow_mut().respond(request),
                auth.refresh(&"C".repeat(43)),
            )
            .err()
            .expect("revoked latest refresh accepted");
            assert_eq!(error.code, "session_revoked");
            let host = state.borrow();
            assert!(!host.tables["app_auth_sessions"][0]["revoked_at"].is_null());
            assert_eq!(
                host.tables["app_auth_sessions"][0]["last_renewed_at"],
                live["last_renewed_at"]
            );
            assert!(host.calls.last().unwrap()["op"] == "commit");
            assert!(
                host.calls
                    .iter()
                    .filter(|call| call["sql"]
                        .as_str()
                        .is_some_and(|sql| sql.starts_with("update \"app_auth_sessions\"")))
                    .all(|call| assignment(call, "expires_at").is_none()),
                "cleanup or revocation changed session expiry"
            );
        }

        #[test]
        fn f05_legacy_selection_delays_without_starving_dead_families() {
            let auth = checked(
                checked(Auth::new(DatabasePort::new(1), &[], &NoHooks))
                    .with_session_policy(3_600, 0),
            );
            let mut host = CleanupHost::default();
            for index in 0..2 {
                let mut legacy = session();
                legacy["id"] = json!(fixture_id(900 + index));
                legacy["first_login_at"] = Value::Null;
                legacy["last_renewed_at"] = Value::Null;
                legacy["created_at"] = json!(checked(timestamp_at(testing::NOW - 8 * DAY)));
                legacy["expires_at"] =
                    json!(checked(timestamp_at(testing::NOW - 8 * DAY + 900_000)));
                host.add("app_auth_sessions", legacy.clone());
                if index == 1 {
                    let mut consumed = refresh();
                    consumed["session_id"] = legacy["id"].clone();
                    consumed["consumed_at"] = json!(checked(timestamp_at(testing::NOW - 60_000)));
                    host.add("app_auth_refresh_tokens", consumed);
                }
            }
            for index in 0..101 {
                let mut legacy = session();
                legacy["id"] = json!(fixture_id(index + 100));
                legacy["first_login_at"] = Value::Null;
                legacy["last_renewed_at"] = Value::Null;
                let age = if index < 100 {
                    30 * 60_000
                } else {
                    2 * 3_600_000
                };
                legacy["created_at"] = json!(checked(timestamp_at(testing::NOW - age)));
                legacy["expires_at"] = json!(checked(timestamp_at(testing::NOW - age + 900_000)));
                host.add("app_auth_sessions", legacy.clone());
                let mut credential = refresh();
                credential["id"] = json!(fixture_id(index + 300));
                credential["session_id"] = legacy["id"].clone();
                credential["token_hash"] = json!(token_digest(&format!("legacy-{index}")));
                credential["created_at"] = json!(checked(timestamp_at(testing::NOW - age)));
                credential["expires_at"] =
                    json!(checked(timestamp_at(testing::NOW - age + 7 * DAY)));
                host.add("app_auth_refresh_tokens", credential);
            }
            let state = Rc::new(RefCell::new(host));
            let state_host = state.clone();
            testing::run(
                move |request| state_host.borrow_mut().respond(request),
                auth.cleanup(),
            );
            let host = state.borrow();
            assert!(
                host.calls.last().unwrap()["op"] == "commit",
                "legacy gaps rolled back cleanup"
            );
            assert!(host.calls.iter().all(|call| call["op"] != "rollback"));
            for index in 0..2 {
                assert!(
                    host.tables["app_auth_sessions"]
                        .iter()
                        .all(|row| row["id"] != fixture_id(900 + index)),
                    "legacy family without an unconsumed refresh survived cleanup"
                );
            }
            assert_eq!(host.deleted, 5, "legacy dead family did not progress");
            assert_eq!(host.tables["app_auth_sessions"].len(), 100);
            assert_eq!(host.tables["app_auth_refresh_tokens"].len(), 100);
            assert_eq!(
                host.calls
                    .iter()
                    .filter(|call| call["sql"]
                        .as_str()
                        .is_some_and(|sql| sql.starts_with("update \"app_auth_sessions\"")))
                    .count(),
                6,
                "live legacy families consumed candidates"
            );
        }

        #[test]
        fn f05_legacy_seven_day_boundary_ignores_invalid_access_expiry() {
            let auth = checked(Auth::new(DatabasePort::new(1), &[], &NoHooks));
            for age in [7 * DAY - 1, 7 * DAY, 7 * DAY + 1] {
                let mut host = CleanupHost::default();
                let mut legacy = session();
                legacy["created_at"] = json!(checked(timestamp_at(testing::NOW - age)));
                legacy["first_login_at"] = Value::Null;
                legacy["last_renewed_at"] = Value::Null;
                host.add("app_auth_sessions", legacy.clone());
                let mut credential = refresh();
                credential["created_at"] = legacy["created_at"].clone();
                credential["expires_at"] =
                    json!(checked(timestamp_at(testing::NOW - age + 7 * DAY)));
                host.add("app_auth_refresh_tokens", credential);
                let state = Rc::new(RefCell::new(host));
                let state_host = state.clone();
                testing::run(
                    move |request| state_host.borrow_mut().respond(request),
                    auth.cleanup(),
                );
                let host = state.borrow();
                let dead = age >= 7 * DAY;
                assert_eq!(host.deleted, if dead { 2 } else { 0 });
                assert_eq!(host.tables["app_auth_sessions"].is_empty(), dead);
                if !dead {
                    assert!(
                        host.calls.iter().all(|call| !call["sql"]
                            .as_str()
                            .is_some_and(|sql| sql.starts_with("update "))),
                        "younger legacy family consumed a cleanup candidate"
                    );
                }
            }
        }

        #[test]
        fn f05_lock_recheck_preserves_concurrent_renewals() {
            let auth = checked(Auth::new(DatabasePort::new(1), &[], &NoHooks));
            let mut host = CleanupHost::default();
            let mut candidate = session();
            candidate["last_renewed_at"] = json!(checked(timestamp_at(testing::NOW - 30 * DAY)));
            host.add("app_auth_sessions", candidate);
            host.add("app_auth_rate_limits", json!({"action": "signin", "key_hash": "a".repeat(64), "attempt_count": 10, "expires_at": checked(timestamp_at(testing::NOW))}));
            let state = Rc::new(RefCell::new(host));
            let state_host = state.clone();
            testing::run(
                move |request| {
                    let mut host = state_host.borrow_mut();
                    let sql = request["sql"].as_str().unwrap_or("");
                    if sql.starts_with("update \"app_auth_sessions\"") {
                        host.tables.get_mut("app_auth_sessions").unwrap()[0]["last_renewed_at"] =
                            json!(checked(timestamp_at(testing::NOW)));
                    }
                    if sql.starts_with("update \"app_auth_rate_limits\"") {
                        let row = &mut host.tables.get_mut("app_auth_rate_limits").unwrap()[0];
                        row["expires_at"] = json!(checked(timestamp_at(testing::NOW + DAY)));
                        row["attempt_count"] = json!(1);
                    }
                    host.respond(request)
                },
                auth.cleanup(),
            );
            let host = state.borrow();
            assert_eq!(host.deleted, 0, "cleanup deleted renewed state");
            assert!(host.tables["app_auth_sessions"][0]["revoked_at"].is_null());
            assert_eq!(host.tables["app_auth_rate_limits"][0]["attempt_count"], 1);
        }

        #[test]
        fn f05_current_policy_uses_first_login_or_latest_renewal() {
            for (legacy, absolute) in [(false, 0), (false, 3_600), (true, 0), (true, 3_600)] {
                let auth = checked(
                    checked(Auth::new(DatabasePort::new(1), &[], &NoHooks))
                        .with_session_policy(3_600, absolute),
                );
                let mut host = CleanupHost::default();
                let mut candidate = session();
                candidate["first_login_at"] = if legacy {
                    Value::Null
                } else {
                    json!(checked(timestamp_at(testing::NOW - 3_600_000)))
                };
                candidate["last_renewed_at"] = if legacy {
                    Value::Null
                } else {
                    json!(checked(timestamp_at(
                        testing::NOW - if absolute == 0 { 3_600_000 } else { 60_000 },
                    )))
                };
                host.add("app_auth_sessions", candidate);
                let mut credential = refresh();
                credential["created_at"] = json!(checked(timestamp_at(
                    testing::NOW - if absolute == 0 { 3_600_000 } else { 60_000 },
                )));
                host.add("app_auth_refresh_tokens", credential);
                let state = Rc::new(RefCell::new(host));
                let state_host = state.clone();
                testing::run(
                    move |request| state_host.borrow_mut().respond(request),
                    auth.cleanup(),
                );
                let host = state.borrow();
                assert_eq!(host.deleted, 2, "cleanup diverged from current policy");
            }
        }

        #[test]
        fn f05_cleanup_failure_keeps_committed_refresh_success() {
            let auth = checked(Auth::new(DatabasePort::new(1), &[], &NoHooks));
            let (result, calls) = run(
                vec![
                    ("query", rows(refresh())),
                    ("begin", json!({"lease": 7})),
                    ("exec", rows(session())),
                    ("exec", rows(refresh())),
                    ("exec", rows(user())),
                    ("exec", rows(refresh())),
                    ("exec", rows(session())),
                    ("exec", rows(refresh())),
                    ("commit", json!({})),
                    ("begin", json!({"lease": 7})),
                    ("exec", json!({"error": "cleanup_private_failure_marker"})),
                    ("rollback", json!({})),
                ],
                auth.refresh(&"A".repeat(43)),
            );
            let tokens = checked(result);
            assert_eq!(tokens.session_id, SESSION_ID);
            assert!(
                !serde_json::to_string(&tokens)
                    .unwrap()
                    .contains("cleanup_private_failure_marker")
            );
            assert!(calls[8]["op"] == "commit" && calls.last().unwrap()["op"] == "rollback");
        }

        #[test]
        fn session_expiry_invariant_signin_commits_with_refresh() {
            let auth = checked(Auth::new(DatabasePort::new(1), &[], &NoHooks));
            let password = "test password for sign-in";
            let mut user = user();
            user["password_hash"] = json!(checked(hash_password(password)));
            let (result, calls) = run(
                vec![
                    ("query", json!({"rows": []})),
                    (
                        "query",
                        rows(
                            json!({"action": "signin", "key_hash": "a".repeat(64), "attempt_count": 1, "expires_at": checked(timestamp_at(testing::NOW + DAY))}),
                        ),
                    ),
                    ("query", rows(user)),
                    ("begin", json!({"lease": 7})),
                    ("exec", rows(session())),
                    ("exec", rows(refresh())),
                    ("commit", json!({})),
                    ("begin", json!({"lease": 7})),
                    ("exec", json!({"rows": []})),
                    ("exec", json!({"rows": []})),
                    ("commit", json!({})),
                ],
                auth.signin("user@example.test", password),
            );
            checked(result);
            let sql = calls[4]["sql"].as_str().unwrap();
            assert!(sql.starts_with("insert into \"app_auth_sessions\""));
            let columns = sql.split_once('(').unwrap().1.split_once(')').unwrap().0;
            let expiry_index = columns
                .split(", ")
                .position(|column| column == "\"expires_at\"")
                .expect("sign-in omitted session expiry");
            assert!(
                checked(parse_timestamp(
                    calls[4]["params"][expiry_index].as_str().unwrap()
                )) >= testing::NOW,
                "sign-in wrote session expiry before issuance"
            );
            assert!(
                calls[5]["sql"]
                    .as_str()
                    .unwrap()
                    .starts_with("insert into \"app_auth_refresh_tokens\"")
            );
            assert!(calls[6]["op"] == "commit");
        }

        #[test]
        fn s4_a05_rotation_preserves_first_login() {
            let auth = checked(Auth::new(DatabasePort::new(1), &[], &NoHooks));
            for legacy in [false, true] {
                let mut session = session();
                session["expires_at"] = json!(checked(timestamp_at(testing::NOW - 1)));
                let original =
                    checked(parse_timestamp(session["first_login_at"].as_str().unwrap()));
                if legacy {
                    session["first_login_at"] = Value::Null;
                    session["last_renewed_at"] = Value::Null;
                }
                let (result, calls) = run(
                    vec![
                        ("query", rows(refresh())),
                        ("begin", json!({"lease": 7})),
                        ("exec", rows(session.clone())),
                        ("exec", rows(refresh())),
                        ("exec", rows(user())),
                        ("exec", rows(refresh())),
                        ("exec", rows(session)),
                        ("exec", rows(refresh())),
                        ("commit", json!({})),
                        ("begin", json!({"lease": 7})),
                        ("exec", json!({"rows": []})),
                        ("exec", json!({"rows": []})),
                        ("commit", json!({})),
                    ],
                    auth.refresh(&"A".repeat(43)),
                );
                let tokens = checked(result);
                assert_eq!(tokens.session_id, SESSION_ID);
                assert_eq!(tokens.user_id, USER_ID);
                assert_eq!(
                    tokens.refresh_expires_at,
                    checked(timestamp_at(testing::NOW + 30 * DAY))
                );
                assert_eq!(
                    checked(parse_timestamp(
                        assignment(&calls[6], "first_login_at")
                            .and_then(Value::as_str)
                            .expect("rotation omitted first login")
                    )),
                    original,
                    "rotation moved first login"
                );
                assert!(
                    assignment(&calls[6], "last_renewed_at")
                        == Some(&json!(checked(timestamp_at(testing::NOW))))
                );
                assert!(
                    checked(parse_timestamp(
                        assignment(&calls[6], "expires_at")
                            .and_then(Value::as_str)
                            .expect("rotation omitted session expiry")
                    )) >= testing::NOW,
                    "rotation wrote session expiry before issuance"
                );
                assert!(
                    calls[7]["sql"]
                        .as_str()
                        .unwrap()
                        .starts_with("insert into \"app_auth_refresh_tokens\"")
                );
                assert!(calls[8]["op"] == "commit");
                assert!(calls.last().unwrap()["op"] == "commit");
            }
        }

        #[test]
        fn s5_a06_a07_unusable_family_rejects_live_access() {
            for (absolute, missing_refresh) in [(0, false), (3_600, false), (0, true)] {
                let auth = checked(
                    checked(Auth::new(DatabasePort::new(1), &[], &NoHooks))
                        .with_session_policy(3_600, absolute),
                );
                let mut host = CleanupHost::default();
                let mut session = session();
                session["token_hash"] = json!(token_digest(&"A".repeat(43)));
                // The access credential remains live when the family must be rejected.
                session["first_login_at"] = json!(checked(timestamp_at(testing::NOW - 3_600_000)));
                session["last_renewed_at"] = json!(checked(timestamp_at(
                    testing::NOW
                        - if absolute == 0 && !missing_refresh {
                            3_600_000
                        } else {
                            600_000
                        }
                )));
                host.add("app_auth_sessions", session);
                if !missing_refresh {
                    host.add("app_auth_refresh_tokens", refresh());
                }
                host.add("app_auth_users", user());
                let state = Rc::new(RefCell::new(host));
                let state_host = state.clone();
                let result = testing::run(
                    move |request| state_host.borrow_mut().respond(request),
                    auth.session(&"A".repeat(43)),
                );
                assert_eq!(
                    result
                        .map(|_| ())
                        .map_err(|error| (error.status, error.code)),
                    Err((401, "invalid_token".into()))
                );
                assert_revoked_and_committed(&state.borrow().calls);
            }

            for absolute in [0, 7_200] {
                let capped = checked(
                    checked(Auth::new(DatabasePort::new(1), &[], &NoHooks))
                        .with_session_policy(86_400, 3_600),
                );
                let expanded = checked(
                    checked(Auth::new(DatabasePort::new(1), &[], &NoHooks))
                        .with_session_policy(86_400, absolute),
                );
                let mut host = CleanupHost::default();
                let mut session = session();
                session["first_login_at"] = json!(checked(timestamp_at(testing::NOW - 3_540_000)));
                session["created_at"] = session["first_login_at"].clone();
                let mut credential = refresh();
                credential["token_hash"] = json!(token_digest(&"A".repeat(43)));
                host.add("app_auth_sessions", session);
                host.add("app_auth_refresh_tokens", credential);
                host.add("app_auth_users", user());
                let state = Rc::new(RefCell::new(host));
                let state_host = state.clone();
                let tokens = checked(testing::run(
                    move |request| state_host.borrow_mut().respond(request),
                    capped.refresh(&"A".repeat(43)),
                ));
                assert_eq!(
                    tokens.refresh_expires_at,
                    checked(timestamp_at(testing::NOW + 60_000))
                );
                assert_eq!(
                    tokens.expires_at,
                    checked(timestamp_at(testing::NOW + 900_000))
                );
                {
                    // Advance the stored timeline by two minutes against the fixed host clock.
                    let mut host = state.borrow_mut();
                    for table in ["app_auth_sessions", "app_auth_refresh_tokens"] {
                        for row in host.tables.get_mut(table).unwrap() {
                            for column in [
                                "created_at",
                                "first_login_at",
                                "last_renewed_at",
                                "expires_at",
                                "consumed_at",
                            ] {
                                if let Some(value) = row[column].as_str() {
                                    row[column] = json!(checked(timestamp_at(
                                        checked(parse_timestamp(value)) - 120_000
                                    )));
                                }
                            }
                        }
                    }
                    host.calls.clear();
                }
                let state_host = state.clone();
                let result = testing::run(
                    move |request| state_host.borrow_mut().respond(request),
                    expanded.session(&tokens.access_token),
                );
                assert_eq!(
                    result
                        .map(|_| ())
                        .map_err(|error| (error.status, error.code)),
                    Err((401, "invalid_token".into())),
                    "policy expansion revived stored-expired access"
                );
                assert_revoked_and_committed(&state.borrow().calls);
            }
        }

        #[test]
        fn policy_changes_reject_stored_or_current_refresh_expiry() {
            for (idle, stored_expired) in [(2_592_000, true), (3_600, false)] {
                let auth = checked(
                    checked(Auth::new(DatabasePort::new(1), &[], &NoHooks))
                        .with_session_policy(idle, 0),
                );
                let mut session = session();
                session["last_renewed_at"] = json!(checked(timestamp_at(testing::NOW - 7_200_000)));
                let mut refresh = refresh();
                refresh["created_at"] = session["last_renewed_at"].clone();
                refresh["expires_at"] = json!(checked(timestamp_at(
                    testing::NOW + if stored_expired { -3_600_000 } else { 30 * DAY },
                )));
                session["token_hash"] = json!(token_digest(&"A".repeat(43)));
                refresh["token_hash"] = json!(token_digest(&"A".repeat(43)));
                let mut host = CleanupHost::default();
                host.add("app_auth_sessions", session);
                host.add("app_auth_refresh_tokens", refresh);
                host.add("app_auth_users", user());
                let state = Rc::new(RefCell::new(host));
                let state_host = state.clone();
                let result = testing::run(
                    move |request| state_host.borrow_mut().respond(request),
                    auth.refresh(&"A".repeat(43)),
                );
                assert_eq!(
                    result
                        .map(|_| ())
                        .map_err(|error| (error.status, error.code)),
                    Err((401, "session_revoked".into())),
                    "expired refresh returned the wrong result"
                );
                assert_revoked_and_committed(&state.borrow().calls);
            }
        }

        #[test]
        fn s6_a05_consumed_refresh_after_old_expiry_revokes_family() {
            let auth = checked(Auth::new(DatabasePort::new(1), &[], &NoHooks));
            let mut refresh = refresh();
            refresh["created_at"] = json!(checked(timestamp_at(testing::NOW - 3 * DAY)));
            refresh["consumed_at"] = json!(checked(timestamp_at(testing::NOW - 2 * DAY)));
            refresh["expires_at"] = json!(checked(timestamp_at(testing::NOW - DAY)));
            let (result, calls) = run(
                vec![
                    ("query", rows(refresh.clone())),
                    ("begin", json!({"lease": 7})),
                    ("exec", rows(session())),
                    ("exec", rows(refresh)),
                    ("exec", rows(user())),
                    ("exec", rows(session())),
                    ("commit", json!({})),
                ],
                auth.refresh(&"A".repeat(43)),
            );
            let error = result.err().expect("consumed refresh accepted");
            assert_eq!(
                (error.status, error.code.as_str()),
                (401, "session_revoked")
            );
            assert_revoked_and_committed(&calls);
        }

        #[test]
        fn s7_a06_access_does_not_renew_family() {
            let auth = checked(Auth::new(DatabasePort::new(1), &[], &NoHooks));
            let (result, calls) = run(
                vec![
                    ("query", rows(session())),
                    ("begin", json!({"lease": 7})),
                    ("exec", rows(session())),
                    ("exec", rows(refresh())),
                    ("exec", rows(user())),
                    ("commit", json!({})),
                ],
                auth.session(&"A".repeat(43)),
            );
            let session = checked(result);
            assert_eq!(session.id, SESSION_ID);
            assert_eq!(session.user.id, USER_ID);
            assert!(
                calls
                    .iter()
                    .all(|call| assignment(call, "last_renewed_at").is_none()),
                "access renewed family"
            );
            assert!(
                calls
                    .iter()
                    .all(|call| assignment(call, "first_login_at").is_none()
                        && assignment(call, "expires_at").is_none())
            );
            assert!(calls.last().unwrap()["op"] == "commit");
        }

        #[test]
        fn session_expiry_invariant_logout_only_revokes() {
            let auth = checked(Auth::new(DatabasePort::new(1), &[], &NoHooks));
            let (result, calls) = run(
                vec![
                    ("query", rows(session())),
                    ("begin", json!({"lease": 7})),
                    ("exec", rows(session())),
                    ("exec", rows(refresh())),
                    ("exec", rows(user())),
                    ("commit", json!({})),
                    ("query", rows(session())),
                ],
                auth.logout(&"A".repeat(43)),
            );
            checked(result);
            assert!(
                calls
                    .iter()
                    .all(|call| assignment(call, "expires_at").is_none())
            );
            assert!(
                assignment(calls.last().unwrap(), "revoked_at")
                    == Some(&json!(checked(timestamp_at(testing::NOW))))
            );
        }
    }

    fn checked<T>(result: Result<T, OperationError>) -> T {
        result.unwrap_or_else(|error| panic!("{}", error.code))
    }

    fn is_expired(policy: &SessionPolicy, now: i64, renewed: i64, stored: i64) -> bool {
        checked(policy.expired(
            now,
            Some(&checked(timestamp_at(0))),
            &checked(timestamp_at(0)),
            Some(&checked(timestamp_at(renewed))),
            None,
            Some(&checked(timestamp_at(stored))),
        ))
    }

    #[test]
    fn a05_successful_rotations_extend_beyond_seven_days() {
        let policy = checked(SessionPolicy::new(2_592_000, 0));
        let mut last_renewed = 0;
        let mut deadline = 30 * DAY;
        for (rotation, expected) in [(29 * DAY, 59 * DAY), (31 * DAY, 61 * DAY)] {
            assert!(!is_expired(&policy, rotation, last_renewed, deadline));
            deadline = policy.expires_at(0, rotation);
            assert_eq!(deadline, expected);
            last_renewed = rotation;
        }
    }

    #[test]
    fn a06_idle_expiry_is_inclusive() {
        let policy = checked(SessionPolicy::new(2_592_000, 0));
        for (now, expired) in [
            (30 * DAY - 1_000, false),
            (30 * DAY, true),
            (30 * DAY + 1_000, true),
        ] {
            assert_eq!(is_expired(&policy, now, 0, 30 * DAY), expired);
        }
    }

    #[test]
    fn a07_absolute_cap_survives_rotation_and_remaining_access_lifetime() {
        let policy = checked(SessionPolicy::new(2_592_000, 5_184_000));
        assert_eq!(policy.expires_at(0, 29 * DAY), 59 * DAY);
        assert_eq!(policy.expires_at(0, 58 * DAY), 60 * DAY);
        for (now, expired) in [
            (60 * DAY - 1_000, false),
            (60 * DAY, true),
            (60 * DAY + 1_000, true),
        ] {
            assert_eq!(is_expired(&policy, now, 58 * DAY, 60 * DAY), expired);
        }
        let last_renewed = 60 * DAY - 1_000;
        assert!(last_renewed + 900_000 > 60 * DAY);
        assert!(is_expired(
            &policy,
            60 * DAY,
            last_renewed,
            policy.expires_at(0, last_renewed)
        ));
        assert_eq!(
            checked(SessionPolicy::new(2_592_000, 3_600)).expires_at(0, 0),
            3_600_000
        );
    }

    #[test]
    fn current_policy_shortening_applies_to_existing_sessions() {
        assert!(!is_expired(
            &checked(SessionPolicy::new(2_592_000, 0)),
            3 * DAY,
            DAY,
            31 * DAY
        ));
        assert!(is_expired(
            &checked(SessionPolicy::new(86_400, 0)),
            3 * DAY,
            DAY,
            31 * DAY
        ));
        assert!(is_expired(
            &checked(SessionPolicy::new(2_592_000, 172_800)),
            3 * DAY,
            DAY,
            31 * DAY
        ));
    }

    #[test]
    fn current_policy_expansion_never_revives_stored_expiry() {
        let policy = checked(SessionPolicy::new(2_592_000, 0));
        for (now, expired) in [(7 * DAY - 1, false), (7 * DAY, true), (8 * DAY, true)] {
            assert_eq!(is_expired(&policy, now, 0, 7 * DAY), expired);
        }
        assert!(checked(policy.expired(
            8 * DAY,
            Some("invalid"),
            "invalid",
            Some("invalid"),
            None,
            Some(&checked(timestamp_at(7 * DAY))),
        )));
        let first_login = checked(timestamp_at(DAY));
        assert!(!checked(policy.expired(
            30 * DAY,
            Some(&first_login),
            &checked(timestamp_at(0)),
            None,
            None,
            None
        )));
    }

    #[test]
    fn legacy_sessions_use_family_creation_and_never_revive_after_expiry() {
        let policy = checked(SessionPolicy::new(2_592_000, 0));
        for (now, expired) in [(7 * DAY - 1, false), (7 * DAY, true), (8 * DAY, true)] {
            assert_eq!(
                checked(policy.expired(
                    now,
                    None,
                    &checked(timestamp_at(0)),
                    None,
                    Some(&checked(timestamp_at(6 * DAY))),
                    Some(&checked(timestamp_at(7 * DAY)))
                )),
                expired
            );
        }
        let capped = checked(SessionPolicy::new(2_592_000, 86_400));
        assert!(checked(capped.expired(
            DAY,
            None,
            &checked(timestamp_at(0)),
            None,
            Some(&checked(timestamp_at(DAY))),
            Some(&checked(timestamp_at(7 * DAY)))
        )));
        assert_eq!(policy.expires_at(0, 6 * DAY), 36 * DAY);
    }

    #[test]
    fn legacy_idle_uses_latest_refresh_issuance_and_expires_at_the_boundary() {
        let policy = checked(SessionPolicy::new(3_600, 0));
        let latest_refresh = 6 * DAY - 600_000;
        for (now, expired) in [
            (6 * DAY, false),
            (latest_refresh + 3_600_000 - 1, false),
            (latest_refresh + 3_600_000, true),
        ] {
            assert_eq!(
                checked(policy.expired(
                    now,
                    None,
                    &checked(timestamp_at(0)),
                    None,
                    Some(&checked(timestamp_at(latest_refresh))),
                    Some(&checked(timestamp_at(7 * DAY))),
                )),
                expired
            );
        }
    }

    #[test]
    fn invalid_policies_and_malformed_timestamps_fail_closed() {
        for (idle, absolute) in [
            (0, 0),
            (3_599, 0),
            (31_536_001, 0),
            (3_600, 1),
            (3_600, 31_536_001),
            (u64::MAX, 0),
        ] {
            assert_eq!(
                SessionPolicy::new(idle, absolute).err().unwrap().code,
                "invalid_session_policy"
            );
        }
        for (idle, absolute) in [(3_600, 0), (31_536_000, 3_600), (3_600, 31_536_000)] {
            assert!(SessionPolicy::new(idle, absolute).is_ok());
        }
        let policy = checked(SessionPolicy::new(2_592_000, 0));
        assert!(
            policy
                .expired(DAY, Some("invalid"), "invalid", None, None, None)
                .is_err()
        );
        assert!(
            policy
                .expired(DAY, None, "invalid", None, None, None)
                .is_err()
        );
    }
}
