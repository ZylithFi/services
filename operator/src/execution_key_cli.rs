//! offline execution-key generation for the private-request hpke recipient.

use std::path::Path;

#[cfg(unix)]
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::io::Write;

use rand_core::{OsRng, RngCore};
use serde::Serialize;
use zeroize::Zeroizing;
use zylith_core::{
    PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyPublicConfig, PrivateExecutionKeyRegistry,
    validate_execution_key_id,
};

const GENERATE_USAGE: &str = "usage: generate-execution-key <key-id> <new-private-config.json>";

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct GeneratedExecutionKeyOutput {
    registry: PrivateExecutionKeyRegistry,
    fingerprint: String,
}

pub(crate) fn generate_execution_key_command(args: &[String]) -> Result<String, String> {
    generate_execution_key_command_with_renderer(args, |output| {
        serde_json::to_string_pretty(output)
            .map_err(|_| "could not serialize public execution key output".to_string())
    })
}

fn generate_execution_key_command_with_renderer(
    args: &[String],
    render_public: impl FnOnce(&GeneratedExecutionKeyOutput) -> Result<String, String>,
) -> Result<String, String> {
    if args.len() != 3 {
        return Err(GENERATE_USAGE.into());
    }
    let key_id = &args[1];
    validate_execution_key_id(key_id).map_err(|error| error.to_string())?;

    let private_key = loop {
        let mut candidate = Zeroizing::new([0_u8; 32]);
        OsRng
            .try_fill_bytes(candidate.as_mut())
            .map_err(|_| "the operating-system random source failed".to_string())?;
        if candidate.iter().any(|byte| *byte != 0) {
            break candidate;
        }
    };
    let private = PrivateExecutionKeyPrivateConfig::from_private_key_bytes(key_id, private_key)
        .map_err(|error| error.to_string())?;
    let registry = PrivateExecutionKeyRegistry {
        keys: vec![PrivateExecutionKeyPublicConfig {
            key_id: private.key_id.clone(),
            algorithm: private.algorithm.clone(),
            public_key: private.public_key.clone(),
        }],
    };
    let fingerprint = registry.fingerprint().map_err(|error| error.to_string())?;
    // finish the public-only serialization before creating a file that contains the secret.
    let public_output = render_public(&GeneratedExecutionKeyOutput {
        registry,
        fingerprint,
    })?;
    let mut serialized = Zeroizing::new(
        serde_json::to_vec_pretty(std::slice::from_ref(&private))
            .map_err(|_| "could not serialize execution key configuration".to_string())?,
    );
    serialized.push(b'\n');
    write_new_private_config(Path::new(&args[2]), serialized.as_slice())?;

    Ok(public_output)
}

#[cfg(unix)]
fn parent_directory(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(unix)]
trait PrivateConfigFsOps {
    fn set_mode_0600(&mut self, file: &File) -> std::io::Result<()>;
    fn metadata(&mut self, file: &File) -> std::io::Result<fs::Metadata>;
    fn verify_regular_mode0600(&mut self, metadata: &fs::Metadata) -> std::io::Result<()>;
    fn write_private(&mut self, file: &mut File, bytes: &[u8]) -> std::io::Result<()>;
    fn sync_private(&mut self, file: &File) -> std::io::Result<()>;
    fn sync_parent(&mut self, path: &Path) -> std::io::Result<()>;
    fn truncate(&mut self, file: &File) -> std::io::Result<()>;
    fn sync_scrub(&mut self, file: &File) -> std::io::Result<()>;
}

#[cfg(unix)]
struct UnixPrivateConfigFsOps;

#[cfg(unix)]
impl PrivateConfigFsOps for UnixPrivateConfigFsOps {
    fn set_mode_0600(&mut self, file: &File) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        file.set_permissions(fs::Permissions::from_mode(0o600))
    }

    fn metadata(&mut self, file: &File) -> std::io::Result<fs::Metadata> {
        file.metadata()
    }

    fn verify_regular_mode0600(&mut self, metadata: &fs::Metadata) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        if metadata.file_type().is_file() && metadata.mode() & 0o777 == 0o600 {
            Ok(())
        } else {
            Err(std::io::Error::other(
                "new execution key file is not a regular mode-0600 file",
            ))
        }
    }

    fn write_private(&mut self, file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
        file.write_all(bytes)
    }

    fn sync_private(&mut self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }

    fn sync_parent(&mut self, path: &Path) -> std::io::Result<()> {
        File::open(parent_directory(path)).and_then(|directory| directory.sync_all())
    }

    fn truncate(&mut self, file: &File) -> std::io::Result<()> {
        file.set_len(0)
    }

    fn sync_scrub(&mut self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }
}

#[cfg(unix)]
fn write_new_private_config(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut operations = UnixPrivateConfigFsOps;
    let mut no_hook = |_: &Path| {};
    write_new_private_config_with_ops(path, bytes, &mut operations, &mut no_hook)
}

#[cfg(unix)]
fn write_new_private_config_with_ops<O: PrivateConfigFsOps>(
    path: &Path,
    bytes: &[u8],
    operations: &mut O,
    before_scrub: &mut dyn FnMut(&Path),
) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            format!(
                "could not create new execution key file {}: {error}",
                path.display()
            )
        })?;
    if let Err(error) = operations.set_mode_0600(&file) {
        return fail_created_file(
            file,
            path,
            format!("could not set mode 0600: {error}"),
            FileVerification::Unconfirmed,
            SecretWriteState::NotStarted,
            operations,
            before_scrub,
        );
    }
    let created = match operations.metadata(&file) {
        Ok(created) => created,
        Err(error) => {
            return fail_created_file(
                file,
                path,
                format!("could not inspect the new execution key file: {error}"),
                FileVerification::Unconfirmed,
                SecretWriteState::NotStarted,
                operations,
                before_scrub,
            );
        }
    };
    if let Err(error) = operations.verify_regular_mode0600(&created) {
        return fail_created_file(
            file,
            path,
            format!("new execution key file regular-mode-0600 verification failed: {error}"),
            FileVerification::Unconfirmed,
            SecretWriteState::NotStarted,
            operations,
            before_scrub,
        );
    }
    if let Err(error) = operations.write_private(&mut file, bytes) {
        return fail_created_file(
            file,
            path,
            format!("private-key write failed: {error}"),
            FileVerification::RegularMode0600,
            SecretWriteState::MayHaveStarted,
            operations,
            before_scrub,
        );
    }
    if let Err(error) = operations.sync_private(&file) {
        return fail_created_file(
            file,
            path,
            format!("private-key file sync failed: {error}"),
            FileVerification::RegularMode0600,
            SecretWriteState::Completed,
            operations,
            before_scrub,
        );
    }
    if let Err(error) = operations.sync_parent(path) {
        return fail_created_file(
            file,
            path,
            format!("parent-directory sync failed: {error}"),
            FileVerification::RegularMode0600,
            SecretWriteState::Completed,
            operations,
            before_scrub,
        );
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum FileVerification {
    Unconfirmed,
    RegularMode0600,
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum SecretWriteState {
    NotStarted,
    MayHaveStarted,
    Completed,
}

#[cfg(unix)]
fn fail_created_file<O: PrivateConfigFsOps>(
    file: File,
    path: &Path,
    cause: String,
    verification: FileVerification,
    secret_write: SecretWriteState,
    operations: &mut O,
    before_scrub: &mut dyn FnMut(&Path),
) -> Result<(), String> {
    before_scrub(path);
    let scrub = operations
        .truncate(&file)
        .and_then(|()| operations.sync_scrub(&file));
    drop(file);
    match scrub {
        Ok(()) => {
            let tombstone = match verification {
                FileVerification::Unconfirmed => {
                    "a zero-length tombstone with unconfirmed permissions requires explicit manual cleanup"
                }
                FileVerification::RegularMode0600 => {
                    "a zero-length mode-0600 tombstone requires explicit manual cleanup"
                }
            };
            let secret = match secret_write {
                SecretWriteState::NotStarted => {
                    "no secret write had started, and the created inode was truncated and synced through its open file descriptor"
                }
                SecretWriteState::MayHaveStarted => {
                    "secret writing may have started, but the created inode was truncated and synced through its open file descriptor"
                }
                SecretWriteState::Completed => {
                    "the complete secret serialization had been written, but the created inode was truncated and synced through its open file descriptor"
                }
            };
            Err(format!(
                "could not durably write new execution key file {}: {cause}; {secret}; if it remains linked, {tombstone}",
                path.display()
            ))
        }
        Err(error) => Err(format!(
            "could not durably write new execution key file {}: {cause}; cleanup could not truncate and sync the created inode through its open file descriptor: {error}; {}; partial secret material may remain and requires secure operator intervention",
            path.display(),
            match secret_write {
                SecretWriteState::NotStarted => "no secret write had started",
                SecretWriteState::MayHaveStarted => "secret writing may have started",
                SecretWriteState::Completed => "the complete secret serialization had been written",
            },
        )),
    }
}

#[cfg(not(unix))]
fn write_new_private_config(_path: &Path, _bytes: &[u8]) -> Result<(), String> {
    Err("execution key generation requires unix create-new mode 0600 semantics".into())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use zylith_core::private_envelope::HPKE_PROFILE_ID;
    #[cfg(unix)]
    use zylith_core::{PrivateExecutionKeyPrivateConfig, PrivateExecutionKeyRegistry};

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);
    const TEST_SECRET: &[u8] = b"s3cr3t-material-9z!";

    fn test_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "zylith-execution-key-{label}-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[cfg(unix)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FsStage {
        SetMode,
        Metadata,
        Verify,
        WritePrivate,
        SyncPrivate,
        SyncParent,
        Truncate,
        SyncScrub,
    }

    #[cfg(unix)]
    struct RecordingFsOps {
        failures: Vec<FsStage>,
        calls: Vec<FsStage>,
        real: UnixPrivateConfigFsOps,
    }

    #[cfg(unix)]
    impl RecordingFsOps {
        fn failing_at(failures: &[FsStage]) -> Self {
            Self {
                failures: failures.to_vec(),
                calls: Vec::new(),
                real: UnixPrivateConfigFsOps,
            }
        }

        fn invoked(&mut self, stage: FsStage) -> std::io::Result<()> {
            self.calls.push(stage);
            if self.failures.contains(&stage) {
                Err(std::io::Error::other(format!(
                    "injected {stage:?} operation failure"
                )))
            } else {
                Ok(())
            }
        }
    }

    #[cfg(unix)]
    impl PrivateConfigFsOps for RecordingFsOps {
        fn set_mode_0600(&mut self, file: &File) -> std::io::Result<()> {
            self.invoked(FsStage::SetMode)?;
            self.real.set_mode_0600(file)
        }

        fn metadata(&mut self, file: &File) -> std::io::Result<fs::Metadata> {
            self.invoked(FsStage::Metadata)?;
            self.real.metadata(file)
        }

        fn verify_regular_mode0600(&mut self, metadata: &fs::Metadata) -> std::io::Result<()> {
            self.invoked(FsStage::Verify)?;
            self.real.verify_regular_mode0600(metadata)
        }

        fn write_private(&mut self, file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
            self.calls.push(FsStage::WritePrivate);
            if self.failures.contains(&FsStage::WritePrivate) {
                let prefix = bytes.len().clamp(1, 16);
                self.real.write_private(file, &bytes[..prefix])?;
                return Err(std::io::Error::other(
                    "injected WritePrivate operation failure after real prefix write",
                ));
            }
            self.real.write_private(file, bytes)
        }

        fn sync_private(&mut self, file: &File) -> std::io::Result<()> {
            self.invoked(FsStage::SyncPrivate)?;
            self.real.sync_private(file)
        }

        fn sync_parent(&mut self, path: &Path) -> std::io::Result<()> {
            self.invoked(FsStage::SyncParent)?;
            self.real.sync_parent(path)
        }

        fn truncate(&mut self, file: &File) -> std::io::Result<()> {
            self.invoked(FsStage::Truncate)?;
            self.real.truncate(file)
        }

        fn sync_scrub(&mut self, file: &File) -> std::io::Result<()> {
            self.invoked(FsStage::SyncScrub)?;
            self.real.sync_scrub(file)
        }
    }

    #[cfg(unix)]
    #[test]
    fn generated_execution_key_is_private_loadable_and_public_output_is_safe() {
        let path = test_path("valid");
        let rendered = generate_execution_key_command(&[
            "generate-execution-key".into(),
            "active-2026".into(),
            path.display().to_string(),
        ])
        .unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        let keys: Vec<PrivateExecutionKeyPrivateConfig> = serde_json::from_str(&raw).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, "active-2026");
        assert_eq!(keys[0].algorithm, HPKE_PROFILE_ID);
        assert_eq!(keys[0].private_key.len(), 64);
        assert_eq!(keys[0].public_key.len(), 64);
        assert!(
            keys[0]
                .private_key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert!(
            keys[0]
                .public_key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );

        let loaded =
            crate::config::load_execution_keys(path.to_str().unwrap(), "active-2026").unwrap();
        let registry = crate::config::active_execution_registry(&loaded, "active-2026").unwrap();
        let fingerprint = registry.fingerprint().unwrap();
        let output: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(output.as_object().unwrap().len(), 2);
        assert_eq!(output["registry"].as_object().unwrap().len(), 1);
        assert_eq!(output["registry"]["keys"].as_array().unwrap().len(), 1);
        assert_eq!(output["registry"]["keys"][0].as_object().unwrap().len(), 3);
        assert_eq!(
            serde_json::from_value::<PrivateExecutionKeyRegistry>(output["registry"].clone())
                .unwrap(),
            registry
        );
        assert_eq!(output["fingerprint"], fingerprint);
        assert!(output.get("private_key").is_none());
        assert!(!rendered.contains("private_key"));
        assert!(!rendered.contains(&keys[0].private_key));

        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn generated_execution_key_refuses_invalid_ids_before_creating_a_file() {
        for id in ["", "UPPER", "-leading", "trailing-", "has.dot"] {
            let path = test_path("invalid-id");
            let error = generate_execution_key_command(&[
                "generate-execution-key".into(),
                id.into(),
                path.display().to_string(),
            ])
            .unwrap_err();
            assert!(error.contains("key id"));
            assert!(!path.exists());
        }
    }

    #[test]
    fn public_output_serialization_failure_happens_before_private_file_creation() {
        let path = test_path("public-render-failure");
        let error = generate_execution_key_command_with_renderer(
            &[
                "generate-execution-key".into(),
                "active".into(),
                path.display().to_string(),
            ],
            |_| Err("injected public serialization failure".into()),
        )
        .unwrap_err();
        assert_eq!(error, "injected public serialization failure");
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn generated_execution_key_never_overwrites_an_existing_file() {
        let path = test_path("existing");
        fs::write(&path, b"preserve me").unwrap();
        let result = generate_execution_key_command(&[
            "generate-execution-key".into(),
            "active".into(),
            path.display().to_string(),
        ]);
        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"preserve me");
        fs::remove_file(path).unwrap();
    }

    #[cfg(not(unix))]
    #[test]
    fn generated_execution_key_fails_closed_without_creating_a_file() {
        let path = test_path("unsupported-platform");
        let error = generate_execution_key_command(&[
            "generate-execution-key".into(),
            "active".into(),
            path.display().to_string(),
        ])
        .unwrap_err();
        assert!(error.contains("requires unix"));
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn generated_execution_key_never_follows_or_replaces_a_symlink() {
        use std::os::unix::fs::symlink;

        let target = test_path("symlink-target");
        let link = test_path("symlink");
        fs::write(&target, b"preserve target").unwrap();
        symlink(&target, &link).unwrap();
        let result = generate_execution_key_command(&[
            "generate-execution-key".into(),
            "active".into(),
            link.display().to_string(),
        ]);
        assert!(result.is_err());
        assert_eq!(fs::read(&target).unwrap(), b"preserve target");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_file(link).unwrap();
        fs::remove_file(target).unwrap();
    }

    #[test]
    fn generated_execution_key_usage_and_failures_have_no_public_output() {
        let path = test_path("usage");
        let error =
            generate_execution_key_command(&["generate-execution-key".into(), "active".into()])
                .unwrap_err();
        assert!(error.contains("usage:"));
        assert!(!path.exists());

        fs::write(&path, b"occupied").unwrap();
        let error = generate_execution_key_command(&[
            "generate-execution-key".into(),
            "active".into(),
            path.display().to_string(),
        ])
        .unwrap_err();
        assert!(!error.contains("private_key"));
        assert!(!error.contains(HPKE_PROFILE_ID));
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn invoked_filesystem_stage_failures_scrub_to_truthful_tombstones() {
        use std::os::unix::fs::PermissionsExt;

        for (failure, expected_calls, expected_cause, verified, secret_state) in [
            (
                FsStage::SetMode,
                vec![FsStage::SetMode, FsStage::Truncate, FsStage::SyncScrub],
                "could not set mode 0600",
                false,
                SecretWriteState::NotStarted,
            ),
            (
                FsStage::Metadata,
                vec![
                    FsStage::SetMode,
                    FsStage::Metadata,
                    FsStage::Truncate,
                    FsStage::SyncScrub,
                ],
                "could not inspect the new execution key file",
                false,
                SecretWriteState::NotStarted,
            ),
            (
                FsStage::Verify,
                vec![
                    FsStage::SetMode,
                    FsStage::Metadata,
                    FsStage::Verify,
                    FsStage::Truncate,
                    FsStage::SyncScrub,
                ],
                "regular-mode-0600 verification failed",
                false,
                SecretWriteState::NotStarted,
            ),
            (
                FsStage::WritePrivate,
                vec![
                    FsStage::SetMode,
                    FsStage::Metadata,
                    FsStage::Verify,
                    FsStage::WritePrivate,
                    FsStage::Truncate,
                    FsStage::SyncScrub,
                ],
                "private-key write failed",
                true,
                SecretWriteState::MayHaveStarted,
            ),
            (
                FsStage::SyncPrivate,
                vec![
                    FsStage::SetMode,
                    FsStage::Metadata,
                    FsStage::Verify,
                    FsStage::WritePrivate,
                    FsStage::SyncPrivate,
                    FsStage::Truncate,
                    FsStage::SyncScrub,
                ],
                "private-key file sync failed",
                true,
                SecretWriteState::Completed,
            ),
            (
                FsStage::SyncParent,
                vec![
                    FsStage::SetMode,
                    FsStage::Metadata,
                    FsStage::Verify,
                    FsStage::WritePrivate,
                    FsStage::SyncPrivate,
                    FsStage::SyncParent,
                    FsStage::Truncate,
                    FsStage::SyncScrub,
                ],
                "parent-directory sync failed",
                true,
                SecretWriteState::Completed,
            ),
        ] {
            let path = test_path("injected-scrub");
            let mut operations = RecordingFsOps::failing_at(&[failure]);
            let mut no_hook = |_: &Path| {};
            let error = write_new_private_config_with_ops(
                &path,
                TEST_SECRET,
                &mut operations,
                &mut no_hook,
            )
            .unwrap_err();
            assert!(error.contains("injected"));
            assert!(error.contains(expected_cause));
            assert!(error.contains("truncated and synced"));
            assert!(error.contains("explicit manual cleanup"));
            assert_eq!(error.contains("mode-0600 tombstone"), verified);
            assert_eq!(error.contains("unconfirmed permissions"), !verified);
            match secret_state {
                SecretWriteState::NotStarted => {
                    assert!(error.contains("no secret write had started"));
                }
                SecretWriteState::MayHaveStarted => {
                    assert!(error.contains("secret writing may have started"));
                }
                SecretWriteState::Completed => {
                    assert!(error.contains("complete secret serialization had been written"));
                }
            }
            assert_safe_error(&error);
            assert_eq!(operations.calls, expected_calls);
            let metadata = fs::metadata(&path).unwrap();
            assert_eq!(metadata.len(), 0);
            if verified {
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            }
            fs::remove_file(path).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn open_descriptor_scrub_preserves_a_concurrent_replacement() {
        let path = test_path("replacement");
        let moved = test_path("moved-created-inode");
        let mut operations = RecordingFsOps::failing_at(&[FsStage::SyncParent]);
        let mut replace = |created: &Path| {
            fs::rename(created, &moved).unwrap();
            fs::write(created, b"replacement").unwrap();
        };
        let error =
            write_new_private_config_with_ops(&path, TEST_SECRET, &mut operations, &mut replace)
                .unwrap_err();
        assert!(error.contains("truncated and synced"));
        assert_safe_error(&error);
        assert_eq!(
            operations.calls,
            [
                FsStage::SetMode,
                FsStage::Metadata,
                FsStage::Verify,
                FsStage::WritePrivate,
                FsStage::SyncPrivate,
                FsStage::SyncParent,
                FsStage::Truncate,
                FsStage::SyncScrub,
            ]
        );
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        assert_eq!(fs::metadata(&moved).unwrap().len(), 0);
        fs::remove_file(path).unwrap();
        fs::remove_file(moved).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn invoked_scrub_failures_report_possible_secret_and_require_intervention() {
        for (cleanup_failure, expected_calls, expected_contents) in [
            (
                FsStage::Truncate,
                vec![
                    FsStage::SetMode,
                    FsStage::Metadata,
                    FsStage::Verify,
                    FsStage::WritePrivate,
                    FsStage::SyncPrivate,
                    FsStage::SyncParent,
                    FsStage::Truncate,
                ],
                TEST_SECRET,
            ),
            (
                FsStage::SyncScrub,
                vec![
                    FsStage::SetMode,
                    FsStage::Metadata,
                    FsStage::Verify,
                    FsStage::WritePrivate,
                    FsStage::SyncPrivate,
                    FsStage::SyncParent,
                    FsStage::Truncate,
                    FsStage::SyncScrub,
                ],
                b"" as &[u8],
            ),
        ] {
            let path = test_path("scrub-failure");
            let mut operations =
                RecordingFsOps::failing_at(&[FsStage::SyncParent, cleanup_failure]);
            let mut no_hook = |_: &Path| {};
            let error = write_new_private_config_with_ops(
                &path,
                TEST_SECRET,
                &mut operations,
                &mut no_hook,
            )
            .unwrap_err();
            assert!(error.contains("cleanup could not truncate and sync"));
            assert!(error.contains("partial secret material may remain"));
            assert!(error.contains("secure operator intervention"));
            assert!(error.contains("complete secret serialization had been written"));
            assert_safe_error(&error);
            assert_eq!(operations.calls, expected_calls);
            assert_eq!(fs::read(&path).unwrap(), expected_contents);
            fs::remove_file(path).unwrap();
        }
    }

    fn assert_safe_error(error: &str) {
        assert!(
            !error
                .as_bytes()
                .windows(TEST_SECRET.len())
                .any(|window| window == TEST_SECRET)
        );
        assert!(!error.contains("private_key"));
        assert!(!error.contains("public_key"));
        assert!(!error.contains("\"key_id\""));
        assert!(!error.contains(HPKE_PROFILE_ID));
        assert!(!error.contains("\"algorithm\""));
        assert!(!error.contains("\"registry\""));
        assert!(!error.contains("\"fingerprint\""));
    }
}
