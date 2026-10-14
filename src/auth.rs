use crate::database::{DatabasePort, TransactionPort};
use crate::orm::{Filter, FindMany};
use crate::private_auth::*;
use crate::server::{OperationError, Session, SessionUser};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use scrypt::{Params, scrypt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{future::Future, pin::Pin};
use subtle::ConstantTimeEq;

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
        self.db
            .transaction(async |tx| self.issue(tx, user).await)
            .await
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
                let legacy_refresh = if session.first_login_at.is_none() {
                    tx.app_auth_refresh_tokens
                        .find_many(FindMany {
                            filter: Some(Filter::all(vec![
                                Filter::eq(
                                    tx.app_auth_refresh_tokens.columns().session_id,
                                    json!(session.id),
                                ),
                                Filter::is_null(tx.app_auth_refresh_tokens.columns().consumed_at),
                            ])),
                            limit: Some(1),
                            ..Default::default()
                        })
                        .await?
                        .into_iter()
                        .next()
                } else {
                    None
                };
                let user = tx
                    .app_auth_users
                    .find_by_id(AppAuthUsersPrimaryKey {
                        id: session.user_id.clone(),
                    })
                    .await?;
                let now = now_millis();
                if self.session_policy.expired(
                    now,
                    session.first_login_at.as_deref(),
                    &session.created_at,
                    session.last_renewed_at.as_deref(),
                    legacy_refresh.as_ref().map(|row| row.created_at.as_str()),
                    legacy_refresh.as_ref().map(|row| row.expires_at.as_str()),
                )? {
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
        outcome.ok_or_else(|| OperationError::new("session_revoked", 401))
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
    let email = value
        .trim_matches(|ch: char| ch.is_whitespace() || ch == '\u{feff}')
        .to_lowercase();
    let parts: Vec<_> = email.split('@').collect();
    let valid_domain = parts
        .get(1)
        .and_then(|domain| domain.rsplit_once('.'))
        .is_some_and(|(head, tail)| !head.is_empty() && !tail.is_empty());
    if email.encode_utf16().count() > 320
        || parts.len() != 2
        || parts[0].is_empty()
        || !valid_domain
        || email
            .chars()
            .any(|ch| ch.is_whitespace() || ch == '\u{feff}' || ch == '\0')
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
        if first_login_at.is_none()
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
    js_sys::Date::now() as i64
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
    fn current_policy_expansion_ignores_old_deadlines_after_transition() {
        let policy = checked(SessionPolicy::new(2_592_000, 0));
        assert!(!is_expired(&policy, 8 * DAY, 0, 7 * DAY));
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
