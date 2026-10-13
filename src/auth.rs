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
        })
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
        let session = rows
            .first()
            .filter(|row| row.revoked_at.is_none())
            .ok_or_else(OperationError::invalid_token)?;
        if expired(&session.expires_at)? {
            return Err(OperationError::invalid_token());
        }
        let user = self
            .db
            .app_auth_users
            .find_by_id(AppAuthUsersPrimaryKey {
                id: session.user_id.clone(),
            })
            .await?
            .filter(|user| {
                user.disabled_at.is_none() && user.session_version == session.user_session_version
            })
            .ok_or_else(OperationError::invalid_token)?;
        Ok(Session {
            id: session.id.clone(),
            user: SessionUser {
                id: user.id,
                email: user.email,
            },
        })
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
                        Filter::is_null(tx.app_auth_sessions.columns().revoked_at),
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
                let valid = match (&current, &user) {
                    (Some(current), Some(user)) => {
                        current.consumed_at.is_none()
                            && !expired(&current.expires_at)?
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
                                revoked_at: Some(Some(timestamp(0)?)),
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
                            consumed_at: Some(Some(timestamp(0)?)),
                            ..Default::default()
                        },
                    )
                    .await?;
                if consumed.is_none() {
                    tx.app_auth_sessions
                        .update(
                            AppAuthSessionsPrimaryKey { id: session.id },
                            AppAuthSessionsUpdate {
                                revoked_at: Some(Some(timestamp(0)?)),
                                ..Default::default()
                            },
                        )
                        .await?;
                    return Ok(None);
                }
                let access_token = random_token()?;
                let refresh_token = random_token()?;
                let expires_at = timestamp(900_000)?;
                tx.app_auth_sessions
                    .update(
                        AppAuthSessionsPrimaryKey {
                            id: session.id.clone(),
                        },
                        AppAuthSessionsUpdate {
                            token_hash: Some(token_digest(&access_token)),
                            expires_at: Some(expires_at.clone()),
                            ..Default::default()
                        },
                    )
                    .await?;
                tx.app_auth_refresh_tokens
                    .insert(AppAuthRefreshTokensInsert {
                        session_id: session.id.clone(),
                        token_hash: token_digest(&refresh_token),
                        expires_at: current.expires_at.clone(),
                        consumed_at: None,
                        created_at: None,
                        id: None,
                    })
                    .await?;
                Ok(Some(Tokens {
                    access_token,
                    refresh_token,
                    expires_at,
                    refresh_expires_at: current.expires_at,
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
        let expires_at = timestamp(900_000)?;
        let refresh_expires_at = timestamp(604_800_000)?;
        let session = tx
            .app_auth_sessions
            .insert(AppAuthSessionsInsert {
                user_id: user.id.clone(),
                token_hash: token_digest(&access_token),
                user_session_version: user.session_version,
                expires_at: expires_at.clone(),
                revoked_at: None,
                id: None,
                created_at: None,
            })
            .await?;
        tx.app_auth_refresh_tokens
            .insert(AppAuthRefreshTokensInsert {
                session_id: session.id.clone(),
                token_hash: token_digest(&refresh_token),
                expires_at: refresh_expires_at.clone(),
                consumed_at: None,
                created_at: None,
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

fn timestamp(delta: i64) -> Result<String, OperationError> {
    DateTime::<Utc>::from_timestamp_millis(js_sys::Date::now() as i64 + delta)
        .map(|date| date.to_rfc3339_opts(SecondsFormat::Millis, true))
        .ok_or_else(OperationError::internal)
}

fn expired(value: &str) -> Result<bool, OperationError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .or_else(|_| DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f%#z"))
        .map_err(|_| OperationError::internal())?;
    Ok(parsed.timestamp_millis() <= js_sys::Date::now() as i64)
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
