//! durable proof-job queue and encrypted content-addressed artifact store.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::Sha256;
use tokio::sync::Mutex;
use zylith_core::extract_bearer_token;
use zylith_core::hash::{felt_from_hex_str, felt_hex, tagged_sha256_hex};
use zylith_proof_job::{
    CompleteProofJob, EnqueueProofJob, ProofJobClaim, ProofJobDescriptor, ProofJobLeaseRequest,
    ProofJobState, ProofJobStatus, ProofWorkerRegistrationGrant, RegisterProofWorker,
    RegisterProofWorkerResponse, WorkerCapabilities, WorkerSessionConfig, constant_time_eq,
    proof_artifact_hash, proof_result_hash,
};

const CONTROL_HEADER: &str = "x-zylith-proof-control-token";
const MONITOR_HEADER: &str = "x-zylith-proof-monitor-token";
const REGISTRATION_HEADER: &str = "x-zylith-worker-registration";
const SESSION_HASH_DOMAIN: &str = "zylith/proof-worker/session/v1:";
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct ProofQueue {
    database_path: Arc<PathBuf>,
    artifacts: Arc<ArtifactStore>,
    control_token: Arc<String>,
    monitor_token: Arc<String>,
    registration_grant_ttl_ms: u64,
    session_ttl_ms: u64,
    worker_max_lifetime_ms: u64,
    lease_duration_ms: u64,
    max_request_bytes: u64,
    completed_retention_ms: u64,
    abandoned_retention_ms: u64,
    write_lock: Arc<Mutex<()>>,
}

#[derive(Debug)]
enum QueueError {
    BadRequest(String),
    Unauthorized,
    NotFound,
    Conflict(String),
    Internal(String),
}

impl QueueError {
    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn safe_message(&self) -> &str {
        match self {
            Self::BadRequest(message) | Self::Conflict(message) => message,
            Self::Unauthorized => "unauthorized",
            Self::NotFound => "not found",
            Self::Internal(message) => {
                eprintln!("proof queue error: {message}");
                "internal error"
            }
        }
    }
}

impl IntoResponse for QueueError {
    fn into_response(self) -> Response {
        (self.status(), self.safe_message().to_owned()).into_response()
    }
}

struct ArtifactStore {
    directory: PathBuf,
    cipher: Aes256Gcm,
}

impl ArtifactStore {
    fn open(directory: PathBuf, key: &[u8; 32]) -> Result<Self, String> {
        fs::create_dir_all(&directory)
            .map_err(|error| format!("proof artifact directory: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("proof artifact permissions: {error}"))?;
        }
        Ok(Self {
            directory,
            cipher: Aes256Gcm::new_from_slice(key).expect("32-byte proof artifact key"),
        })
    }

    fn path(&self, hash: &str) -> Result<PathBuf, QueueError> {
        if !zylith_proof_job::is_hash(hash) {
            return Err(QueueError::BadRequest("invalid artifact hash".into()));
        }
        Ok(self.directory.join(hash))
    }

    fn put(&self, expected_hash: &str, bytes: &[u8]) -> Result<(), QueueError> {
        if proof_artifact_hash(bytes) != expected_hash {
            return Err(QueueError::BadRequest(
                "proof artifact hash does not match the descriptor".into(),
            ));
        }
        let path = self.path(expected_hash)?;
        if path.exists() {
            self.get(expected_hash)?;
            return Ok(());
        }
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: bytes,
                    aad: expected_hash.as_bytes(),
                },
            )
            .map_err(|_| QueueError::Internal("proof artifact encryption failed".into()))?;
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&ciphertext);
        let temporary = path.with_extension("tmp");
        let mut file = fs::File::create(&temporary)
            .map_err(|error| QueueError::Internal(format!("proof artifact write: {error}")))?;
        file.write_all(&sealed)
            .and_then(|()| file.sync_all())
            .map_err(|error| QueueError::Internal(format!("proof artifact write: {error}")))?;
        fs::rename(&temporary, &path)
            .map_err(|error| QueueError::Internal(format!("proof artifact commit: {error}")))?;
        fs::File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| QueueError::Internal(format!("proof artifact commit: {error}")))?;
        Ok(())
    }

    fn get(&self, expected_hash: &str) -> Result<Vec<u8>, QueueError> {
        let sealed = fs::read(self.path(expected_hash)?)
            .map_err(|error| QueueError::Internal(format!("proof artifact read: {error}")))?;
        if sealed.len() < 12 {
            return Err(QueueError::Internal("proof artifact is truncated".into()));
        }
        let (nonce, ciphertext) = sealed.split_at(12);
        let bytes = self
            .cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: expected_hash.as_bytes(),
                },
            )
            .map_err(|_| QueueError::Internal("proof artifact authentication failed".into()))?;
        if proof_artifact_hash(&bytes) != expected_hash {
            return Err(QueueError::Internal(
                "proof artifact hash is corrupt".into(),
            ));
        }
        Ok(bytes)
    }

    fn remove(&self, expected_hash: &str) -> Result<(), QueueError> {
        let path = self.path(expected_hash)?;
        match fs::remove_file(path) {
            Ok(()) => fs::File::open(&self.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| QueueError::Internal(format!("proof artifact delete: {error}"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(QueueError::Internal(format!(
                "proof artifact delete: {error}"
            ))),
        }
    }

    fn remove_orphans(&self, referenced: &BTreeSet<String>) -> Result<u64, QueueError> {
        let mut removed = 0_u64;
        for entry in fs::read_dir(&self.directory)
            .map_err(|error| QueueError::Internal(format!("proof artifact scan: {error}")))?
        {
            let entry = entry
                .map_err(|error| QueueError::Internal(format!("proof artifact scan: {error}")))?;
            if !entry
                .file_type()
                .map_err(|error| QueueError::Internal(format!("proof artifact scan: {error}")))?
                .is_file()
            {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if referenced.contains(&name) {
                continue;
            }
            fs::remove_file(entry.path()).map_err(|error| {
                QueueError::Internal(format!("orphaned proof artifact delete: {error}"))
            })?;
            removed += 1;
        }
        if removed != 0 {
            fs::File::open(&self.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| {
                    QueueError::Internal(format!("orphaned proof artifact delete: {error}"))
                })?;
        }
        Ok(removed)
    }
}

#[derive(Clone)]
struct WorkerIdentity {
    worker_id: String,
    capabilities: WorkerCapabilities,
    session_not_after_unix_ms: u64,
}

impl ProofQueue {
    pub fn open(config: ProofQueueConfig) -> Result<Self, String> {
        if config.registration_grant_ttl_ms == 0
            || config.lease_duration_ms == 0
            || config.session_ttl_ms <= config.lease_duration_ms
            || config.worker_max_lifetime_ms < config.session_ttl_ms
            || config.max_request_bytes == 0
            || config.completed_retention_ms == 0
            || config.abandoned_retention_ms <= config.completed_retention_ms
        {
            return Err("proof queue timing or size limits are inconsistent".into());
        }
        if config.control_token.is_empty()
            || config.monitor_token.is_empty()
            || constant_time_eq(&config.control_token, &config.monitor_token)
        {
            return Err("proof queue control and monitoring tokens must be distinct".into());
        }
        open_database(&config.database_path)?;
        Ok(Self {
            database_path: Arc::new(config.database_path),
            artifacts: Arc::new(ArtifactStore::open(
                config.artifact_directory,
                &config.data_key,
            )?),
            control_token: Arc::new(config.control_token),
            monitor_token: Arc::new(config.monitor_token),
            registration_grant_ttl_ms: config.registration_grant_ttl_ms,
            session_ttl_ms: config.session_ttl_ms,
            worker_max_lifetime_ms: config.worker_max_lifetime_ms,
            lease_duration_ms: config.lease_duration_ms,
            max_request_bytes: config.max_request_bytes,
            completed_retention_ms: config.completed_retention_ms,
            abandoned_retention_ms: config.abandoned_retention_ms,
            write_lock: Arc::new(Mutex::new(())),
        })
    }

    fn connection(&self) -> Result<Connection, QueueError> {
        open_database(&self.database_path).map_err(QueueError::Internal)
    }

    fn require_control(&self, headers: &HeaderMap) -> Result<(), QueueError> {
        let provided = headers
            .get(CONTROL_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if constant_time_eq(provided, &self.control_token) {
            Ok(())
        } else {
            Err(QueueError::Unauthorized)
        }
    }

    fn require_monitor(&self, headers: &HeaderMap) -> Result<(), QueueError> {
        let provided = headers
            .get(MONITOR_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if constant_time_eq(provided, &self.monitor_token) {
            Ok(())
        } else {
            Err(QueueError::Unauthorized)
        }
    }

    fn require_registration_grant(&self, headers: &HeaderMap) -> Result<(), QueueError> {
        let provided = headers
            .get(REGISTRATION_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if provided.is_empty() {
            return Err(QueueError::Unauthorized);
        }
        let now = now_ms();
        let connection = self.connection()?;
        let valid = connection
            .query_row(
                "SELECT 1 FROM proof_worker_grants
                 WHERE token_hash = ?1 AND expires_at_unix_ms > ?2
                   AND consumed_at_unix_ms IS NULL",
                params![session_hash(provided), now as i64],
                |_| Ok(()),
            )
            .optional()
            .map_err(|error| QueueError::Internal(format!("grant authorization: {error}")))?
            .is_some();
        if valid {
            Ok(())
        } else {
            Err(QueueError::Unauthorized)
        }
    }

    fn worker_token<'a>(&self, headers: &'a HeaderMap) -> Result<&'a str, QueueError> {
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(extract_bearer_token)
            .filter(|token| !token.is_empty())
            .ok_or(QueueError::Unauthorized)
    }

    fn enqueue_sync(&self, request: EnqueueProofJob) -> Result<ProofJobStatus, QueueError> {
        request
            .descriptor
            .validate()
            .map_err(QueueError::BadRequest)?;
        for value in [
            &request.descriptor.chain_id,
            &request.descriptor.exchange_address,
            &request.descriptor.proof_program_address,
            &request.descriptor.proof_version,
            &request.descriptor.program_variant,
            &request.descriptor.virtual_program_hash,
            &request.descriptor.starknet_os_output_version,
            &request.descriptor.starknet_os_config_hash,
            &request.descriptor.base_block_hash,
            &request.descriptor.statement_commitment,
        ] {
            normalize_protocol_felt(value).map_err(QueueError::BadRequest)?;
        }
        for value in [
            request.descriptor.input_state_root.as_deref(),
            request.descriptor.expected_output_state_root.as_deref(),
            request.descriptor.expected_message.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            normalize_protocol_felt(value).map_err(QueueError::BadRequest)?;
        }
        let bytes = serde_json::to_vec(&request.request)
            .map_err(|error| QueueError::BadRequest(format!("proof request: {error}")))?;
        if bytes.len() as u64 != request.descriptor.request_bytes
            || bytes.len() as u64 > self.max_request_bytes
            || proof_artifact_hash(&bytes) != request.descriptor.request_hash
        {
            return Err(QueueError::BadRequest(
                "proof request bytes do not match the descriptor".into(),
            ));
        }
        self.artifacts
            .put(&request.descriptor.request_hash, &bytes)?;
        let connection = self.connection()?;
        let existing = load_status(&connection, &request.descriptor.job_id)?;
        if let Some(existing) = existing {
            if existing.descriptor == request.descriptor {
                return Ok(existing);
            }
            if request.descriptor.base_block_number > existing.descriptor.base_block_number {
                let descriptor_json = serde_json::to_string(&request.descriptor)
                    .map_err(|error| QueueError::Internal(error.to_string()))?;
                connection
                    .execute(
                        "UPDATE proof_jobs SET descriptor_json = ?1, state = 'PENDING',
                            worker_id = NULL, lease_id = NULL,
                            lease_expires_at_unix_ms = NULL, result_json = NULL,
                            result_hash = NULL, updated_at_unix_ms = ?2
                         WHERE job_id = ?3",
                        params![
                            descriptor_json,
                            request.descriptor.created_at_unix_ms as i64,
                            request.descriptor.job_id,
                        ],
                    )
                    .map_err(|error| QueueError::Internal(format!("proof job refresh: {error}")))?;
                return load_status(&connection, &request.descriptor.job_id)?.ok_or_else(|| {
                    QueueError::Internal("refreshed proof job cannot be read".into())
                });
            }
            return Err(QueueError::Conflict(
                "proof job id is already bound to a newer proving attempt".into(),
            ));
        }
        let descriptor_json = serde_json::to_string(&request.descriptor)
            .map_err(|error| QueueError::Internal(error.to_string()))?;
        connection
            .execute(
                "INSERT INTO proof_jobs (
                    job_id, descriptor_json, state, attempts, created_at_unix_ms,
                    updated_at_unix_ms
                 ) VALUES (?1, ?2, 'PENDING', 0, ?3, ?3)",
                params![
                    request.descriptor.job_id,
                    descriptor_json,
                    request.descriptor.created_at_unix_ms as i64,
                ],
            )
            .map_err(|error| QueueError::Internal(format!("proof job insert: {error}")))?;
        load_status(&connection, &request.descriptor.job_id)?
            .ok_or_else(|| QueueError::Internal("inserted proof job cannot be read".into()))
    }

    fn status_sync(&self, job_id: &str) -> Result<ProofJobStatus, QueueError> {
        load_status(&self.connection()?, job_id)?.ok_or(QueueError::NotFound)
    }

    fn delete_job_sync(&self, job_id: &str) -> Result<(), QueueError> {
        let connection = self.connection()?;
        let descriptor = connection
            .query_row(
                "SELECT descriptor_json FROM proof_jobs WHERE job_id = ?1",
                [job_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| QueueError::Internal(format!("proof job delete read: {error}")))?
            .ok_or(QueueError::NotFound)?;
        let descriptor: ProofJobDescriptor = serde_json::from_str(&descriptor)
            .map_err(|error| QueueError::Internal(format!("job decode: {error}")))?;
        connection
            .execute("DELETE FROM proof_jobs WHERE job_id = ?1", [job_id])
            .map_err(|error| QueueError::Internal(format!("proof job delete: {error}")))?;
        if !artifact_is_referenced(&connection, &descriptor.request_hash)? {
            self.artifacts.remove(&descriptor.request_hash)?;
        }
        Ok(())
    }

    fn prune_sync(&self) -> Result<u64, QueueError> {
        let now = now_ms();
        let complete_cutoff = now.saturating_sub(self.completed_retention_ms);
        let abandoned_cutoff = now.saturating_sub(self.abandoned_retention_ms);
        let connection = self.connection()?;
        connection
            .execute(
                "UPDATE proof_jobs SET state = 'PENDING', worker_id = NULL, lease_id = NULL,
                    lease_expires_at_unix_ms = NULL, updated_at_unix_ms = ?1
                 WHERE state IN ('CLAIMED', 'PROVING')
                   AND lease_expires_at_unix_ms <= ?1",
                [now as i64],
            )
            .map_err(|error| QueueError::Internal(format!("expired lease recovery: {error}")))?;
        let mut statement = connection
            .prepare(
                "SELECT job_id FROM proof_jobs
                 WHERE (state = 'COMPLETE' AND updated_at_unix_ms <= ?1)
                    OR (state = 'PENDING' AND updated_at_unix_ms <= ?2)",
            )
            .map_err(|error| QueueError::Internal(format!("proof retention query: {error}")))?;
        let job_ids = statement
            .query_map(
                params![complete_cutoff as i64, abandoned_cutoff as i64],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| QueueError::Internal(format!("proof retention query: {error}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| QueueError::Internal(format!("proof retention row: {error}")))?;
        drop(statement);
        let mut deleted = 0_u64;
        for job_id in job_ids {
            self.delete_job_sync(&job_id)?;
            deleted += 1;
        }
        let mut referenced = BTreeSet::new();
        let mut statement = connection
            .prepare("SELECT descriptor_json FROM proof_jobs")
            .map_err(|error| QueueError::Internal(format!("artifact retention query: {error}")))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| QueueError::Internal(format!("artifact retention query: {error}")))?;
        for row in rows {
            let descriptor: ProofJobDescriptor = serde_json::from_str(&row.map_err(|error| {
                QueueError::Internal(format!("artifact retention row: {error}"))
            })?)
            .map_err(|error| QueueError::Internal(format!("job decode: {error}")))?;
            referenced.insert(descriptor.request_hash);
        }
        self.artifacts.remove_orphans(&referenced)?;
        Ok(deleted)
    }

    pub async fn prune(&self) -> Result<u64, String> {
        let queue = self.clone();
        let _guard = self.write_lock.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || queue.prune_sync())
            .await
            .map_err(|error| format!("proof retention task: {error}"))?
            .map_err(|error| error.safe_message().to_owned())
    }

    fn issue_registration_grant_sync(
        &self,
        request: RegisterProofWorker,
    ) -> Result<ProofWorkerRegistrationGrant, QueueError> {
        validate_worker(&request)?;
        let token = random_hex();
        let now = now_ms();
        let expires = now.saturating_add(self.registration_grant_ttl_ms);
        let capabilities = serde_json::to_string(&request.capabilities)
            .map_err(|error| QueueError::Internal(error.to_string()))?;
        let connection = self.connection()?;
        connection
            .execute(
                "DELETE FROM proof_worker_grants
                 WHERE expires_at_unix_ms <= ?1 OR consumed_at_unix_ms IS NOT NULL",
                [now as i64],
            )
            .map_err(|error| QueueError::Internal(format!("grant cleanup: {error}")))?;
        connection
            .execute(
                "INSERT INTO proof_worker_grants (
                    token_hash, worker_id, capabilities_json, expires_at_unix_ms
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    session_hash(&token),
                    request.worker_id,
                    capabilities,
                    expires as i64,
                ],
            )
            .map_err(|error| QueueError::Internal(format!("grant insert: {error}")))?;
        Ok(ProofWorkerRegistrationGrant {
            token,
            expires_at_unix_ms: expires,
        })
    }

    fn register_sync(
        &self,
        provided_grant: &str,
        request: RegisterProofWorker,
    ) -> Result<RegisterProofWorkerResponse, QueueError> {
        validate_worker(&request)?;
        let now = now_ms();
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| QueueError::Internal(format!("registration transaction: {error}")))?;
        let grant = transaction
            .query_row(
                "SELECT worker_id, capabilities_json, expires_at_unix_ms, consumed_at_unix_ms
                 FROM proof_worker_grants WHERE token_hash = ?1",
                [session_hash(provided_grant)],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| QueueError::Internal(format!("grant read: {error}")))?
            .ok_or(QueueError::Unauthorized)?;
        let granted_capabilities: WorkerCapabilities = serde_json::from_str(&grant.1)
            .map_err(|error| QueueError::Internal(format!("grant decode: {error}")))?;
        if grant.0 != request.worker_id
            || granted_capabilities != request.capabilities
            || grant.2 <= now as i64
            || grant.3.is_some()
        {
            return Err(QueueError::Unauthorized);
        }
        transaction
            .execute(
                "UPDATE proof_worker_grants SET consumed_at_unix_ms = ?1
                 WHERE token_hash = ?2 AND consumed_at_unix_ms IS NULL",
                params![now as i64, session_hash(provided_grant)],
            )
            .map_err(|error| QueueError::Internal(format!("grant consume: {error}")))?;
        let response = create_session(
            &transaction,
            &request.worker_id,
            &request.capabilities,
            now,
            now.saturating_add(self.worker_max_lifetime_ms),
            self.session_ttl_ms,
            self.lease_duration_ms,
            self.max_request_bytes,
            provided_grant,
        )?;
        transaction
            .commit()
            .map_err(|error| QueueError::Internal(format!("registration commit: {error}")))?;
        Ok(response)
    }

    fn refresh_session_sync(&self, token: &str) -> Result<RegisterProofWorkerResponse, QueueError> {
        let worker = self.authorize_worker(token)?;
        let now = now_ms();
        if now >= worker.session_not_after_unix_ms {
            return Err(QueueError::Unauthorized);
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| QueueError::Internal(format!("session refresh: {error}")))?;
        let response = create_session(
            &transaction,
            &worker.worker_id,
            &worker.capabilities,
            now,
            worker.session_not_after_unix_ms,
            self.session_ttl_ms,
            self.lease_duration_ms,
            self.max_request_bytes,
            token,
        )?;
        transaction
            .execute(
                "DELETE FROM proof_worker_sessions WHERE token_hash = ?1",
                [session_hash(token)],
            )
            .map_err(|error| QueueError::Internal(format!("session revoke: {error}")))?;
        transaction
            .commit()
            .map_err(|error| QueueError::Internal(format!("session refresh: {error}")))?;
        Ok(response)
    }

    fn authorize_worker(&self, token: &str) -> Result<WorkerIdentity, QueueError> {
        let now = now_ms();
        let connection = self.connection()?;
        let row = connection
            .query_row(
                "SELECT worker_id, capabilities_json, expires_at_unix_ms,
                        session_not_after_unix_ms
                 FROM proof_worker_sessions WHERE token_hash = ?1",
                [session_hash(token)],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| QueueError::Internal(format!("session read: {error}")))?
            .ok_or(QueueError::Unauthorized)?;
        if row.2 <= now as i64 {
            return Err(QueueError::Unauthorized);
        }
        Ok(WorkerIdentity {
            worker_id: row.0,
            capabilities: serde_json::from_str(&row.1)
                .map_err(|error| QueueError::Internal(format!("session decode: {error}")))?,
            session_not_after_unix_ms: u64::try_from(row.3)
                .map_err(|_| QueueError::Internal("session deadline is invalid".into()))?,
        })
    }

    fn claim_sync(&self, token: &str) -> Result<Option<ProofJobClaim>, QueueError> {
        let worker = self.authorize_worker(token)?;
        let now = now_ms();
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| QueueError::Internal(format!("claim transaction: {error}")))?;
        transaction
            .execute(
                "UPDATE proof_jobs SET
                    state = 'PENDING', worker_id = NULL, lease_id = NULL,
                    lease_expires_at_unix_ms = NULL, updated_at_unix_ms = ?1
                 WHERE state IN ('CLAIMED', 'PROVING')
                   AND lease_expires_at_unix_ms <= ?1",
                [now as i64],
            )
            .map_err(|error| QueueError::Internal(format!("expired lease recovery: {error}")))?;
        let candidates = {
            let mut statement = transaction
                .prepare(
                    "SELECT descriptor_json FROM proof_jobs
                     WHERE state = 'PENDING' ORDER BY created_at_unix_ms, job_id",
                )
                .map_err(|error| QueueError::Internal(format!("claim query: {error}")))?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|error| QueueError::Internal(format!("claim query: {error}")))?;
            let mut candidates = Vec::new();
            for row in rows {
                let encoded =
                    row.map_err(|error| QueueError::Internal(format!("claim row: {error}")))?;
                let descriptor: ProofJobDescriptor = serde_json::from_str(&encoded)
                    .map_err(|error| QueueError::Internal(format!("job decode: {error}")))?;
                if worker.capabilities.supports(&descriptor) {
                    candidates.push(descriptor);
                    break;
                }
            }
            candidates
        };
        let Some(descriptor) = candidates.into_iter().next() else {
            transaction
                .commit()
                .map_err(|error| QueueError::Internal(format!("claim commit: {error}")))?;
            return Ok(None);
        };
        let lease_id = random_hex();
        let lease_expires = now.saturating_add(self.lease_duration_ms);
        let updated = transaction
            .execute(
                "UPDATE proof_jobs SET
                    state = 'CLAIMED', worker_id = ?1, lease_id = ?2,
                    lease_expires_at_unix_ms = ?3, attempts = attempts + 1,
                    updated_at_unix_ms = ?4
                 WHERE job_id = ?5 AND state = 'PENDING'",
                params![
                    worker.worker_id,
                    lease_id,
                    lease_expires as i64,
                    now as i64,
                    descriptor.job_id,
                ],
            )
            .map_err(|error| QueueError::Internal(format!("claim update: {error}")))?;
        if updated != 1 {
            return Err(QueueError::Conflict(
                "proof job was claimed concurrently".into(),
            ));
        }
        transaction
            .commit()
            .map_err(|error| QueueError::Internal(format!("claim commit: {error}")))?;
        Ok(Some(ProofJobClaim {
            artifact_path: format!("/internal/proof-jobs/{}/artifact", descriptor.job_id),
            descriptor,
            lease_id,
            lease_expires_at_unix_ms: lease_expires,
        }))
    }

    fn start_sync(
        &self,
        token: &str,
        job_id: &str,
        request: ProofJobLeaseRequest,
    ) -> Result<ProofJobStatus, QueueError> {
        let worker = self.authorize_worker(token)?;
        let now = now_ms();
        let expires = now.saturating_add(self.lease_duration_ms);
        let connection = self.connection()?;
        let updated = connection
            .execute(
                "UPDATE proof_jobs SET state = 'PROVING', lease_expires_at_unix_ms = ?1,
                    updated_at_unix_ms = ?2
                 WHERE job_id = ?3 AND worker_id = ?4 AND lease_id = ?5
                   AND state IN ('CLAIMED', 'PROVING') AND lease_expires_at_unix_ms > ?2",
                params![
                    expires as i64,
                    now as i64,
                    job_id,
                    worker.worker_id,
                    request.lease_id,
                ],
            )
            .map_err(|error| QueueError::Internal(format!("proof start: {error}")))?;
        if updated != 1 {
            return Err(QueueError::Conflict("proof lease is stale".into()));
        }
        self.status_sync(job_id)
    }

    fn artifact_sync(&self, token: &str, job_id: &str) -> Result<Vec<u8>, QueueError> {
        let worker = self.authorize_worker(token)?;
        let now = now_ms();
        let connection = self.connection()?;
        let descriptor_json = connection
            .query_row(
                "SELECT descriptor_json FROM proof_jobs
                 WHERE job_id = ?1 AND worker_id = ?2
                   AND state IN ('CLAIMED', 'PROVING') AND lease_expires_at_unix_ms > ?3",
                params![job_id, worker.worker_id, now as i64],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| QueueError::Internal(format!("artifact authorization: {error}")))?
            .ok_or(QueueError::Unauthorized)?;
        let descriptor: ProofJobDescriptor = serde_json::from_str(&descriptor_json)
            .map_err(|error| QueueError::Internal(format!("job decode: {error}")))?;
        self.artifacts.get(&descriptor.request_hash)
    }

    fn complete_sync(
        &self,
        token: &str,
        job_id: &str,
        request: CompleteProofJob,
    ) -> Result<ProofJobStatus, QueueError> {
        let worker = self.authorize_worker(token)?;
        let now = now_ms();
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| QueueError::Internal(format!("completion transaction: {error}")))?;
        let row = transaction
            .query_row(
                "SELECT descriptor_json, state, worker_id, lease_id,
                        lease_expires_at_unix_ms, result_hash
                 FROM proof_jobs WHERE job_id = ?1",
                [job_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| QueueError::Internal(format!("completion read: {error}")))?
            .ok_or(QueueError::NotFound)?;
        let descriptor: ProofJobDescriptor = serde_json::from_str(&row.0)
            .map_err(|error| QueueError::Internal(format!("job decode: {error}")))?;
        validate_result(&descriptor, &request)?;
        let result_hash = proof_result_hash(&request.result).map_err(QueueError::BadRequest)?;
        if row.1 == "COMPLETE" {
            if row.5.as_deref() == Some(&result_hash) {
                transaction
                    .commit()
                    .map_err(|error| QueueError::Internal(format!("completion commit: {error}")))?;
                return self.status_sync(job_id);
            }
            return Err(QueueError::Conflict(
                "proof job already has a different result".into(),
            ));
        }
        if row.2.as_deref() != Some(&worker.worker_id)
            || row.3.as_deref() != Some(&request.lease_id)
            || row.4.is_none_or(|expires| expires <= now as i64)
            || !matches!(row.1.as_str(), "CLAIMED" | "PROVING")
        {
            return Err(QueueError::Conflict("proof lease is stale".into()));
        }
        let result_json = serde_json::to_string(&request.result)
            .map_err(|error| QueueError::Internal(error.to_string()))?;
        transaction
            .execute(
                "UPDATE proof_jobs SET state = 'COMPLETE', result_json = ?1,
                    result_hash = ?2, lease_expires_at_unix_ms = NULL,
                    updated_at_unix_ms = ?3 WHERE job_id = ?4",
                params![result_json, result_hash, now as i64, job_id],
            )
            .map_err(|error| QueueError::Internal(format!("proof completion: {error}")))?;
        transaction
            .commit()
            .map_err(|error| QueueError::Internal(format!("completion commit: {error}")))?;
        self.status_sync(job_id)
    }

    fn health_sync(&self) -> Result<serde_json::Value, QueueError> {
        let connection = self.connection()?;
        let now = now_ms();
        let (pending, active, oldest_pending, expired_active) = connection
            .query_row(
                "SELECT
                    SUM(CASE WHEN state = 'PENDING' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN state IN ('CLAIMED', 'PROVING') THEN 1 ELSE 0 END),
                    MIN(CASE WHEN state = 'PENDING' THEN updated_at_unix_ms END),
                    SUM(CASE WHEN state IN ('CLAIMED', 'PROVING')
                        AND lease_expires_at_unix_ms <= ?1 THEN 1 ELSE 0 END)
                 FROM proof_jobs",
                [now as i64],
                |row| {
                    Ok((
                        row.get::<_, Option<u64>>(0)?,
                        row.get::<_, Option<u64>>(1)?,
                        row.get::<_, Option<u64>>(2)?,
                        row.get::<_, Option<u64>>(3)?,
                    ))
                },
            )
            .map_err(|error| QueueError::Internal(format!("proof health: {error}")))?;
        let workers = connection
            .query_row(
                "SELECT COUNT(DISTINCT worker_id) FROM proof_worker_sessions
                 WHERE expires_at_unix_ms > ?1",
                [now as i64],
                |row| row.get::<_, u64>(0),
            )
            .map_err(|error| QueueError::Internal(format!("worker health: {error}")))?;
        Ok(serde_json::json!({
            "status": "ok",
            "pending_jobs": pending.unwrap_or(0),
            "active_jobs": active.unwrap_or(0),
            "registered_workers": workers,
            "oldest_pending_age_ms": oldest_pending.map_or(0, |created| now.saturating_sub(created)),
            "expired_active_jobs": expired_active.unwrap_or(0),
        }))
    }
}

pub struct ProofQueueConfig {
    pub database_path: PathBuf,
    pub artifact_directory: PathBuf,
    pub data_key: [u8; 32],
    pub control_token: String,
    pub monitor_token: String,
    pub registration_grant_ttl_ms: u64,
    pub session_ttl_ms: u64,
    pub worker_max_lifetime_ms: u64,
    pub lease_duration_ms: u64,
    pub max_request_bytes: u64,
    pub completed_retention_ms: u64,
    pub abandoned_retention_ms: u64,
}

pub fn router(queue: ProofQueue) -> Router {
    let max_body_bytes = usize::try_from(queue.max_request_bytes)
        .unwrap_or(usize::MAX)
        .saturating_add(1 << 20);
    let control = Router::new()
        .route("/internal/proof-jobs", post(enqueue))
        .route(
            "/internal/proof-jobs/{job_id}",
            get(status).delete(delete_job),
        )
        .route(
            "/internal/proof-workers/grants",
            post(issue_registration_grant),
        )
        .route_layer(middleware::from_fn_with_state(
            queue.clone(),
            require_control_middleware,
        ));
    let monitor = Router::new()
        .route("/internal/proof-queue/health", get(internal_health))
        .route_layer(middleware::from_fn_with_state(
            queue.clone(),
            require_monitor_middleware,
        ));
    let registration = Router::new()
        .route("/internal/proof-workers/register", post(register))
        .route_layer(middleware::from_fn_with_state(
            queue.clone(),
            require_registration_middleware,
        ))
        .layer(DefaultBodyLimit::max(64 * 1024));
    let workers = Router::new()
        .route("/internal/proof-workers/refresh", post(refresh_session))
        .route("/internal/proof-jobs/claim", post(claim))
        .route("/internal/proof-jobs/{job_id}/start", post(start))
        .route("/internal/proof-jobs/{job_id}/artifact", get(artifact))
        .route("/internal/proof-jobs/{job_id}/complete", post(complete))
        .route_layer(middleware::from_fn_with_state(
            queue.clone(),
            require_worker_middleware,
        ));
    Router::new()
        .route("/health/proof-queue", get(health))
        .merge(control)
        .merge(monitor)
        .merge(registration)
        .merge(workers)
        .with_state(queue)
        .layer(DefaultBodyLimit::max(max_body_bytes))
}

async fn require_control_middleware(
    State(queue): State<ProofQueue>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, QueueError> {
    queue.require_control(request.headers())?;
    Ok(next.run(request).await)
}

async fn require_monitor_middleware(
    State(queue): State<ProofQueue>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, QueueError> {
    queue.require_monitor(request.headers())?;
    Ok(next.run(request).await)
}

async fn require_registration_middleware(
    State(queue): State<ProofQueue>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, QueueError> {
    let headers = request.headers().clone();
    blocking("registration auth", move || {
        queue.require_registration_grant(&headers)
    })
    .await?;
    Ok(next.run(request).await)
}

async fn require_worker_middleware(
    State(queue): State<ProofQueue>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, QueueError> {
    let token = queue.worker_token(request.headers())?.to_owned();
    blocking("worker auth", move || queue.authorize_worker(&token)).await?;
    Ok(next.run(request).await)
}

/// runs a blocking queue operation off the async runtime.
async fn blocking<T: Send + 'static>(
    label: &str,
    task: impl FnOnce() -> Result<T, QueueError> + Send + 'static,
) -> Result<T, QueueError> {
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|error| QueueError::Internal(format!("{label} task: {error}")))?
}

async fn enqueue(
    State(queue): State<ProofQueue>,
    Json(request): Json<EnqueueProofJob>,
) -> Result<Json<ProofJobStatus>, QueueError> {
    let _guard = queue.write_lock.clone().lock_owned().await;
    blocking("enqueue", move || queue.enqueue_sync(request))
        .await
        .map(Json)
}

async fn status(
    State(queue): State<ProofQueue>,
    Path(job_id): Path<String>,
) -> Result<Json<ProofJobStatus>, QueueError> {
    blocking("status", move || queue.status_sync(&job_id))
        .await
        .map(Json)
}

async fn delete_job(
    State(queue): State<ProofQueue>,
    Path(job_id): Path<String>,
) -> Result<StatusCode, QueueError> {
    let _guard = queue.write_lock.clone().lock_owned().await;
    blocking("delete", move || queue.delete_job_sync(&job_id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn register(
    State(queue): State<ProofQueue>,
    headers: HeaderMap,
    Json(request): Json<RegisterProofWorker>,
) -> Result<Json<RegisterProofWorkerResponse>, QueueError> {
    let grant = headers
        .get(REGISTRATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let _guard = queue.write_lock.clone().lock_owned().await;
    blocking("registration", move || queue.register_sync(&grant, request))
        .await
        .map(Json)
}

async fn issue_registration_grant(
    State(queue): State<ProofQueue>,
    Json(request): Json<RegisterProofWorker>,
) -> Result<Json<ProofWorkerRegistrationGrant>, QueueError> {
    let _guard = queue.write_lock.clone().lock_owned().await;
    blocking("grant", move || {
        queue.issue_registration_grant_sync(request)
    })
    .await
    .map(Json)
}

async fn refresh_session(
    State(queue): State<ProofQueue>,
    headers: HeaderMap,
) -> Result<Json<RegisterProofWorkerResponse>, QueueError> {
    let token = queue.worker_token(&headers)?.to_owned();
    let _guard = queue.write_lock.clone().lock_owned().await;
    blocking("refresh", move || queue.refresh_session_sync(&token))
        .await
        .map(Json)
}

async fn claim(
    State(queue): State<ProofQueue>,
    headers: HeaderMap,
) -> Result<Response, QueueError> {
    let token = queue.worker_token(&headers)?.to_owned();
    let _guard = queue.write_lock.clone().lock_owned().await;
    let claim = blocking("claim", move || queue.claim_sync(&token)).await?;
    Ok(match claim {
        Some(claim) => Json(claim).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    })
}

async fn start(
    State(queue): State<ProofQueue>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Json(request): Json<ProofJobLeaseRequest>,
) -> Result<Json<ProofJobStatus>, QueueError> {
    let token = queue.worker_token(&headers)?.to_owned();
    let _guard = queue.write_lock.clone().lock_owned().await;
    blocking("start", move || queue.start_sync(&token, &job_id, request))
        .await
        .map(Json)
}

async fn artifact(
    State(queue): State<ProofQueue>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Result<Response, QueueError> {
    let token = queue.worker_token(&headers)?.to_owned();
    let bytes = blocking("artifact", move || queue.artifact_sync(&token, &job_id)).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "private, no-store"),
        ],
        bytes,
    )
        .into_response())
}

async fn complete(
    State(queue): State<ProofQueue>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Json(request): Json<CompleteProofJob>,
) -> Result<Json<ProofJobStatus>, QueueError> {
    let token = queue.worker_token(&headers)?.to_owned();
    let _guard = queue.write_lock.clone().lock_owned().await;
    blocking("completion", move || {
        queue.complete_sync(&token, &job_id, request)
    })
    .await
    .map(Json)
}

async fn health(State(queue): State<ProofQueue>) -> Result<Json<serde_json::Value>, QueueError> {
    blocking("health", move || {
        queue
            .connection()
            .map(|_| serde_json::json!({"status": "ok"}))
    })
    .await
    .map(Json)
}

async fn internal_health(
    State(queue): State<ProofQueue>,
) -> Result<Json<serde_json::Value>, QueueError> {
    blocking("health", move || queue.health_sync())
        .await
        .map(Json)
}

fn open_database(path: &FsPath) -> Result<Connection, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("proof database directory: {error}"))?;
    }
    let connection = Connection::open(path).map_err(|error| format!("proof database: {error}"))?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|error| error.to_string())?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|error| error.to_string())?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|error| error.to_string())?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS proof_jobs (
                job_id TEXT PRIMARY KEY,
                descriptor_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('PENDING', 'CLAIMED', 'PROVING', 'COMPLETE')),
                worker_id TEXT,
                lease_id TEXT,
                lease_expires_at_unix_ms INTEGER,
                attempts INTEGER NOT NULL,
                result_json TEXT,
                result_hash TEXT,
                created_at_unix_ms INTEGER NOT NULL,
                updated_at_unix_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_proof_jobs_state_created
                ON proof_jobs(state, created_at_unix_ms);
            CREATE TABLE IF NOT EXISTS proof_worker_sessions (
                token_hash TEXT PRIMARY KEY,
                worker_id TEXT NOT NULL,
                capabilities_json TEXT NOT NULL,
                expires_at_unix_ms INTEGER NOT NULL,
                session_not_after_unix_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_proof_worker_sessions_expiry
                ON proof_worker_sessions(expires_at_unix_ms);
            CREATE TABLE IF NOT EXISTS proof_worker_grants (
                token_hash TEXT PRIMARY KEY,
                worker_id TEXT NOT NULL,
                capabilities_json TEXT NOT NULL,
                expires_at_unix_ms INTEGER NOT NULL,
                consumed_at_unix_ms INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_proof_worker_grants_expiry
                ON proof_worker_grants(expires_at_unix_ms);",
        )
        .map_err(|error| format!("proof database schema: {error}"))?;
    Ok(connection)
}

fn load_status(
    connection: &Connection,
    job_id: &str,
) -> Result<Option<ProofJobStatus>, QueueError> {
    let row = connection
        .query_row(
            "SELECT descriptor_json, state, attempts, lease_expires_at_unix_ms, result_json
             FROM proof_jobs WHERE job_id = ?1",
            [job_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|error| QueueError::Internal(format!("proof job read: {error}")))?;
    let Some((descriptor, state, attempts, expires, result)) = row else {
        return Ok(None);
    };
    Ok(Some(ProofJobStatus {
        descriptor: serde_json::from_str(&descriptor)
            .map_err(|error| QueueError::Internal(format!("job decode: {error}")))?,
        state: match state.as_str() {
            "PENDING" => ProofJobState::Pending,
            "CLAIMED" => ProofJobState::Claimed,
            "PROVING" => ProofJobState::Proving,
            "COMPLETE" => ProofJobState::Complete,
            _ => return Err(QueueError::Internal("invalid proof job state".into())),
        },
        attempts,
        lease_expires_at_unix_ms: expires.and_then(|value| u64::try_from(value).ok()),
        result: result
            .map(|encoded| {
                serde_json::from_str(&encoded)
                    .map_err(|error| QueueError::Internal(format!("proof result decode: {error}")))
            })
            .transpose()?,
    }))
}

fn artifact_is_referenced(connection: &Connection, request_hash: &str) -> Result<bool, QueueError> {
    let mut statement = connection
        .prepare("SELECT descriptor_json FROM proof_jobs")
        .map_err(|error| QueueError::Internal(format!("artifact reference query: {error}")))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| QueueError::Internal(format!("artifact reference query: {error}")))?;
    for row in rows {
        let descriptor: ProofJobDescriptor =
            serde_json::from_str(&row.map_err(|error| {
                QueueError::Internal(format!("artifact reference row: {error}"))
            })?)
            .map_err(|error| QueueError::Internal(format!("job decode: {error}")))?;
        if descriptor.request_hash == request_hash {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_worker(request: &RegisterProofWorker) -> Result<(), QueueError> {
    if request.worker_id.is_empty()
        || request.worker_id.len() > 128
        || !request
            .worker_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(QueueError::BadRequest("worker id is invalid".into()));
    }
    for value in [
        &request.capabilities.prover_build_id,
        &request.capabilities.proof_version,
        &request.capabilities.program_variant,
        &request.capabilities.virtual_program_hash,
        &request.capabilities.starknet_os_output_version,
        &request.capabilities.starknet_os_config_hash,
    ] {
        if value.is_empty() || value.len() > 256 {
            return Err(QueueError::BadRequest(
                "worker capability is invalid".into(),
            ));
        }
    }
    Ok(())
}

fn validate_result(
    descriptor: &ProofJobDescriptor,
    request: &CompleteProofJob,
) -> Result<(), QueueError> {
    if request.prover_build_id != descriptor.prover_build_id
        || request.request_hash != descriptor.request_hash
        || request.result.proof.trim().is_empty()
        || request.result.proof.len() > MAX_PROOF_BYTES
        || request.result.proof_facts.len() != 9
    {
        return Err(QueueError::BadRequest(
            "proof result does not match the job".into(),
        ));
    }
    let normalize = |value: &str| normalize_protocol_felt(value).map_err(QueueError::BadRequest);
    let facts = request
        .result
        .proof_facts
        .iter()
        .map(|value| normalize(value))
        .collect::<Result<Vec<_>, _>>()?;
    let expected_message = descriptor
        .expected_message
        .as_deref()
        .map(normalize)
        .transpose()?;
    if facts[0] != normalize(&descriptor.proof_version)?
        || facts[1] != normalize(&descriptor.program_variant)?
        || facts[2] != normalize(&descriptor.virtual_program_hash)?
        || facts[3] != normalize(&descriptor.starknet_os_output_version)?
        || facts[4] != felt_hex(&starknet_crypto::Felt::from(descriptor.base_block_number))
        || facts[5] != normalize(&descriptor.base_block_hash)?
        || facts[6] != normalize(&descriptor.starknet_os_config_hash)?
        || facts[7] != "0x1"
        || expected_message.is_some_and(|expected| facts[8] != expected)
    {
        return Err(QueueError::BadRequest(
            "proof facts do not match the pinned job".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_session(
    connection: &Connection,
    worker_id: &str,
    capabilities: &WorkerCapabilities,
    now: u64,
    session_not_after_unix_ms: u64,
    session_ttl_ms: u64,
    lease_duration_ms: u64,
    max_request_bytes: u64,
    mac_secret: &str,
) -> Result<RegisterProofWorkerResponse, QueueError> {
    let token = random_hex();
    let expires = now
        .saturating_add(session_ttl_ms)
        .min(session_not_after_unix_ms);
    let capabilities_json = serde_json::to_string(capabilities)
        .map_err(|error| QueueError::Internal(error.to_string()))?;
    connection
        .execute(
            "DELETE FROM proof_worker_sessions WHERE expires_at_unix_ms <= ?1",
            [now as i64],
        )
        .map_err(|error| QueueError::Internal(format!("session cleanup: {error}")))?;
    connection
        .execute(
            "INSERT INTO proof_worker_sessions (
                token_hash, worker_id, capabilities_json, expires_at_unix_ms,
                session_not_after_unix_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                session_hash(&token),
                worker_id,
                capabilities_json,
                expires as i64,
                session_not_after_unix_ms as i64,
            ],
        )
        .map_err(|error| QueueError::Internal(format!("session insert: {error}")))?;
    let config = WorkerSessionConfig {
        schema_version: zylith_proof_job::PROOF_JOB_SCHEMA_VERSION,
        worker_id: worker_id.to_owned(),
        capabilities: capabilities.clone(),
        session_expires_at_unix_ms: expires,
        lease_duration_ms,
        max_request_bytes,
    };
    let config_mac = config_mac(mac_secret, &config)?;
    Ok(RegisterProofWorkerResponse {
        token,
        config,
        config_mac,
    })
}

fn config_mac(secret: &str, config: &WorkerSessionConfig) -> Result<String, QueueError> {
    let encoded = serde_json::to_vec(config)
        .map_err(|error| QueueError::Internal(format!("worker config encode: {error}")))?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|_| QueueError::Internal("worker config mac key is invalid".into()))?;
    mac.update(&encoded);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn normalize_protocol_felt(value: &str) -> Result<String, String> {
    if value.starts_with("0x") {
        return felt_from_hex_str(value)
            .map(|felt| felt_hex(&felt))
            .map_err(|_| "proof fact is not a felt".into());
    }
    if value.is_empty() || value.len() > 31 || !value.is_ascii() {
        return Err("proof fact is not a felt or short string".into());
    }
    Ok(felt_hex(&starknet_crypto::Felt::from_bytes_be_slice(
        value.as_bytes(),
    )))
}

fn session_hash(token: &str) -> String {
    tagged_sha256_hex(SESSION_HASH_DOMAIN, token.as_bytes())
}

fn random_hex() -> String {
    let mut value = [0_u8; 32];
    OsRng.fill_bytes(&mut value);
    hex::encode(value)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;
    use zylith_proof_job::{PROOF_JOB_SCHEMA_VERSION, ProofPayload, ProofStatementKind};

    fn directory(name: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        std::env::temp_dir().join(format!(
            "zylith-proof-queue-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    fn queue(name: &str, lease_duration_ms: u64) -> ProofQueue {
        open_queue(directory(name), lease_duration_ms)
    }

    fn open_queue(root: PathBuf, lease_duration_ms: u64) -> ProofQueue {
        ProofQueue::open(ProofQueueConfig {
            database_path: root.join("queue.sqlite"),
            artifact_directory: root.join("artifacts"),
            data_key: [7; 32],
            control_token: "control".into(),
            monitor_token: "monitor".into(),
            registration_grant_ttl_ms: 60_000,
            session_ttl_ms: 120_000,
            worker_max_lifetime_ms: 4 * 60 * 60_000,
            lease_duration_ms,
            max_request_bytes: 1 << 20,
            completed_retention_ms: 60_000,
            abandoned_retention_ms: 120_000,
        })
        .unwrap()
    }

    fn job() -> EnqueueProofJob {
        let request =
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"starknet_proveTransaction"});
        let bytes = serde_json::to_vec(&request).unwrap();
        let mut descriptor = ProofJobDescriptor {
            schema_version: PROOF_JOB_SCHEMA_VERSION,
            job_id: String::new(),
            statement_kind: ProofStatementKind::Transition,
            transition_id: "transition:0x1".into(),
            epoch_id: Some(1),
            protocol_version: "zylith-v1".into(),
            config_version: "release".into(),
            prover_build_id: "build".into(),
            chain_id: "0x1".into(),
            exchange_address: "0x2".into(),
            proof_program_address: "0x3".into(),
            program_entrypoint: "compile_transition_proof".into(),
            proof_version: "0x4".into(),
            program_variant: "VIRTUAL_SNOS".into(),
            virtual_program_hash: "0x5".into(),
            starknet_os_output_version: "VIRTUAL_SNOS0".into(),
            starknet_os_config_hash: "0x6".into(),
            base_block_number: 10,
            base_block_hash: "0xb".into(),
            input_state_root: Some("0x7".into()),
            expected_output_state_root: Some("0x8".into()),
            statement_commitment: "0x9".into(),
            expected_message: Some("0xa".into()),
            witness_hash: "1".repeat(64),
            request_hash: proof_artifact_hash(&bytes),
            request_bytes: bytes.len() as u64,
            created_at_unix_ms: now_ms(),
        };
        descriptor.job_id = descriptor.expected_job_id().unwrap();
        EnqueueProofJob {
            descriptor,
            request,
        }
    }

    fn worker() -> RegisterProofWorker {
        RegisterProofWorker {
            worker_id: "worker-1".into(),
            capabilities: WorkerCapabilities {
                prover_build_id: "build".into(),
                proof_version: "0x4".into(),
                program_variant: "VIRTUAL_SNOS".into(),
                virtual_program_hash: "0x5".into(),
                starknet_os_output_version: "VIRTUAL_SNOS0".into(),
                starknet_os_config_hash: "0x6".into(),
            },
        }
    }

    fn register(queue: &ProofQueue, worker: RegisterProofWorker) -> RegisterProofWorkerResponse {
        let grant = queue.issue_registration_grant_sync(worker.clone()).unwrap();
        queue.register_sync(&grant.token, worker).unwrap()
    }

    fn proof(lease_id: String, request_hash: String) -> CompleteProofJob {
        CompleteProofJob {
            lease_id,
            prover_build_id: "build".into(),
            request_hash,
            result: ProofPayload {
                proof: "proof-bytes".into(),
                proof_facts: vec![
                    "0x4".into(),
                    "0x5649525455414c5f534e4f53".into(),
                    "0x5".into(),
                    "0x5649525455414c5f534e4f5330".into(),
                    "0xa".into(),
                    "0xb".into(),
                    "0x6".into(),
                    "0x1".into(),
                    "0xa".into(),
                ],
            },
        }
    }

    #[test]
    fn duplicate_jobs_and_results_are_idempotent() {
        let queue = queue("idempotent", 60_000);
        let job = job();
        let first = queue.enqueue_sync(job.clone()).unwrap();
        assert_eq!(queue.enqueue_sync(job.clone()).unwrap(), first);
        let session = register(&queue, worker());
        let claim = queue.claim_sync(&session.token).unwrap().unwrap();
        queue
            .start_sync(
                &session.token,
                &claim.descriptor.job_id,
                ProofJobLeaseRequest {
                    lease_id: claim.lease_id.clone(),
                },
            )
            .unwrap();
        let result = proof(claim.lease_id, claim.descriptor.request_hash.clone());
        let completed = queue
            .complete_sync(&session.token, &claim.descriptor.job_id, result.clone())
            .unwrap();
        assert_eq!(completed.state, ProofJobState::Complete);
        assert_eq!(
            queue
                .complete_sync(&session.token, &claim.descriptor.job_id, result)
                .unwrap()
                .state,
            ProofJobState::Complete
        );
    }

    #[test]
    fn registration_grants_are_one_time_and_refresh_rotates_the_session() {
        let queue = queue("worker-credentials", 60_000);
        let registration = worker();
        let grant = queue
            .issue_registration_grant_sync(registration.clone())
            .unwrap();
        let first = queue
            .register_sync(&grant.token, registration.clone())
            .unwrap();
        assert!(matches!(
            queue.register_sync(&grant.token, registration),
            Err(QueueError::Unauthorized)
        ));
        let refreshed = queue.refresh_session_sync(&first.token).unwrap();
        assert!(matches!(
            queue.authorize_worker(&first.token),
            Err(QueueError::Unauthorized)
        ));
        assert_eq!(
            queue.authorize_worker(&refreshed.token).unwrap().worker_id,
            "worker-1"
        );
    }

    #[test]
    fn a_newer_base_replaces_a_stale_attempt_and_revokes_its_lease() {
        let queue = queue("proof-refresh", 60_000);
        let first = job();
        queue.enqueue_sync(first).unwrap();
        let session = register(&queue, worker());
        let stale = queue.claim_sync(&session.token).unwrap().unwrap();

        let mut refreshed = job();
        refreshed.request = serde_json::json!({
            "jsonrpc":"2.0",
            "id":2,
            "method":"starknet_proveTransaction"
        });
        let bytes = serde_json::to_vec(&refreshed.request).unwrap();
        refreshed.descriptor.base_block_number += 1;
        refreshed.descriptor.base_block_hash = "0xc".into();
        refreshed.descriptor.request_hash = proof_artifact_hash(&bytes);
        refreshed.descriptor.request_bytes = bytes.len() as u64;
        refreshed.descriptor.created_at_unix_ms += 1;
        refreshed.descriptor.job_id = refreshed.descriptor.expected_job_id().unwrap();
        assert_eq!(
            queue
                .enqueue_sync(refreshed)
                .unwrap()
                .descriptor
                .base_block_number,
            11
        );
        let stale_result = proof(stale.lease_id, stale.descriptor.request_hash);
        assert!(
            queue
                .complete_sync(&session.token, &stale.descriptor.job_id, stale_result)
                .is_err()
        );
        assert_eq!(
            queue.status_sync(&stale.descriptor.job_id).unwrap().state,
            ProofJobState::Pending
        );
    }

    #[test]
    fn expired_lease_is_reclaimed_and_late_result_is_rejected() {
        let queue = queue("lease", 1);
        let job = job();
        let job_id = job.descriptor.job_id.clone();
        queue.enqueue_sync(job).unwrap();
        let first = register(&queue, worker());
        let first_claim = queue.claim_sync(&first.token).unwrap().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let mut second_worker = worker();
        second_worker.worker_id = "worker-2".into();
        let second = register(&queue, second_worker);
        let second_claim = queue.claim_sync(&second.token).unwrap().unwrap();
        assert_ne!(first_claim.lease_id, second_claim.lease_id);
        let late = proof(first_claim.lease_id, first_claim.descriptor.request_hash);
        assert!(matches!(
            queue.complete_sync(&first.token, &job_id, late),
            Err(QueueError::Conflict(_))
        ));
    }

    #[test]
    fn a_proving_worker_can_renew_its_lease() {
        let queue = queue("lease-renewal", 60_000);
        queue.enqueue_sync(job()).unwrap();
        let session = register(&queue, worker());
        let claim = queue.claim_sync(&session.token).unwrap().unwrap();
        let request = ProofJobLeaseRequest {
            lease_id: claim.lease_id.clone(),
        };
        std::thread::sleep(std::time::Duration::from_millis(2));
        let first_renewal = queue
            .start_sync(&session.token, &claim.descriptor.job_id, request.clone())
            .unwrap();
        assert!(first_renewal.lease_expires_at_unix_ms.unwrap() > claim.lease_expires_at_unix_ms);
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second_renewal = queue
            .start_sync(&session.token, &claim.descriptor.job_id, request)
            .unwrap();
        assert!(
            second_renewal.lease_expires_at_unix_ms.unwrap()
                > first_renewal.lease_expires_at_unix_ms.unwrap()
        );
        assert_eq!(
            queue
                .complete_sync(
                    &session.token,
                    &claim.descriptor.job_id,
                    proof(claim.lease_id, claim.descriptor.request_hash),
                )
                .unwrap()
                .state,
            ProofJobState::Complete
        );
    }

    #[test]
    fn completed_jobs_and_witness_artifacts_are_pruned() {
        let queue = queue("retention", 60_000);
        let job = job();
        let job_id = job.descriptor.job_id.clone();
        let request_hash = job.descriptor.request_hash.clone();
        queue.enqueue_sync(job).unwrap();
        let session = register(&queue, worker());
        let claim = queue.claim_sync(&session.token).unwrap().unwrap();
        queue
            .complete_sync(
                &session.token,
                &job_id,
                proof(claim.lease_id, claim.descriptor.request_hash),
            )
            .unwrap();
        queue
            .connection()
            .unwrap()
            .execute(
                "UPDATE proof_jobs SET updated_at_unix_ms = 0 WHERE job_id = ?1",
                [&job_id],
            )
            .unwrap();
        assert_eq!(queue.prune_sync().unwrap(), 1);
        assert!(matches!(
            queue.status_sync(&job_id),
            Err(QueueError::NotFound)
        ));
        assert!(!queue.artifacts.path(&request_hash).unwrap().exists());
    }

    #[test]
    fn restart_preserves_jobs_and_immutable_artifacts() {
        let root = directory("restart");
        let first = open_queue(root.clone(), 60_000);
        let job = job();
        let job_id = job.descriptor.job_id.clone();
        let request_hash = job.descriptor.request_hash.clone();
        let expected = serde_json::to_vec(&job.request).unwrap();
        first.enqueue_sync(job).unwrap();
        drop(first);

        let recovered = open_queue(root, 60_000);
        assert_eq!(
            recovered.status_sync(&job_id).unwrap().state,
            ProofJobState::Pending
        );
        assert_eq!(recovered.artifacts.get(&request_hash).unwrap(), expected);
    }

    #[test]
    fn corrupted_artifact_fails_closed() {
        let queue = queue("corrupt", 60_000);
        let job = job();
        let request_hash = job.descriptor.request_hash.clone();
        queue.enqueue_sync(job).unwrap();
        fs::write(queue.artifacts.path(&request_hash).unwrap(), b"corrupt").unwrap();
        assert!(matches!(
            queue.artifacts.get(&request_hash),
            Err(QueueError::Internal(_))
        ));
    }

    #[test]
    fn stale_worker_cannot_claim_a_job_for_another_build() {
        let queue = queue("stale-worker", 60_000);
        queue.enqueue_sync(job()).unwrap();
        let mut stale = worker();
        stale.capabilities.prover_build_id = "old-build".into();
        let session = register(&queue, stale);
        assert!(queue.claim_sync(&session.token).unwrap().is_none());
        assert_eq!(queue.health_sync().unwrap()["pending_jobs"], 1);
    }

    #[tokio::test]
    async fn public_health_does_not_expose_private_queue_activity() {
        let queue = queue("health-privacy", 60_000);
        queue.enqueue_sync(job()).unwrap();
        let app = router(queue);
        let public = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health/proof-queue")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let public = to_bytes(public.into_body(), 1 << 20).await.unwrap();
        assert_eq!(public.as_ref(), br#"{"status":"ok"}"#);

        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/proof-queue/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let internal = app
            .oneshot(
                Request::builder()
                    .uri("/internal/proof-queue/health")
                    .header(MONITOR_HEADER, "monitor")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let internal = to_bytes(internal.into_body(), 1 << 20).await.unwrap();
        let internal: serde_json::Value = serde_json::from_slice(&internal).unwrap();
        assert_eq!(internal["pending_jobs"], 1);
    }

    #[tokio::test]
    async fn monitoring_cannot_issue_worker_grants() {
        let app = router(queue("monitor-isolation", 60_000));
        let response = app
            .oneshot(
                Request::post("/internal/proof-workers/grants")
                    .header(MONITOR_HEADER, "monitor")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&worker()).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unauthorized_large_json_is_rejected_before_parsing() {
        let app = router(queue("preparse-auth", 60_000));
        let response = app
            .oneshot(
                Request::post("/internal/proof-jobs")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(vec![b'['; 1 << 20]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
