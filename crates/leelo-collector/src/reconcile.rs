use crate::Result;
use serde::Deserialize;
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};

const INPUT_LIMIT: usize = 1024 * 1024;
const JOURNAL_LIMIT: usize = 64 * 1024;
const TARGET_LIMIT: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema_version: u8,
    updated_at_ms: u64,
    valid_for_seconds: u32,
    boots: Vec<ExpectedBoot>,
    enrollments: Vec<Enrollment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedBoot {
    target: String,
    boot_id: String,
    requested_at_ms: u64,
    deadline_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    journal: PathBuf,
    created_at_ms: u64,
    production_boot_test_passed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observations {
    schema_version: u8,
    updated_at_ms: u64,
    boots: Vec<BootObservation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootObservation {
    target: String,
    boot_id: String,
    observed_at_ms: u64,
    outcome: BootOutcome,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BootOutcome {
    Success,
    Failure,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
fn read_held(path: &Path, limit: usize) -> Result<(Vec<u8>, FileIdentity)> {
    use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};
    use std::os::unix::fs::MetadataExt;
    let file: File = openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?
    .into();
    let metadata = file.metadata()?;
    let owner = metadata.uid();
    if !metadata.is_file()
        || metadata.len() > limit as u64
        || (owner != 0 && owner != rustix::process::geteuid().as_raw())
        || metadata.mode() & 0o022 != 0
    {
        return Err(
            "input must be a bounded regular file with trusted ownership and writers".into(),
        );
    }
    // Kernel filesystem IDs: ext2/3/4, btrfs, xfs, tmpfs, ramfs, overlayfs, f2fs.
    // Remote, userspace and pseudo filesystems are deliberately outside this reader.
    if !matches!(
        rustix::fs::fstatfs(&file)?.f_type as u32,
        0xef53 | 0x9123_683e | 0x5846_5342 | 0x0102_1994 | 0x8584_58f6 | 0x794c_7630 | 0xf2f5_2010
    ) {
        return Err("reconciliation inputs require a supported local filesystem".into());
    }
    let identity = FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let mut data = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut data)?;
    if data.len() > limit {
        return Err("reconciliation input exceeds bound".into());
    }
    Ok((data, identity))
}

#[cfg(not(target_os = "linux"))]
fn read_held(_: &Path, _: usize) -> Result<(Vec<u8>, FileIdentity)> {
    Err("secure reconciliation file reads require Linux".into())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    read_held(path, INPUT_LIMIT).map(|(bytes, _)| bytes)
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o640))?;
    }
    file.write_all(bytes)?;
    file.flush()?;
    file.persist(path)?;
    Ok(())
}

fn fresh(timestamp: u64, now: u64, validity: u32) -> bool {
    timestamp <= now && now - timestamp <= u64::from(validity) * 1000
}

fn reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"_-.:".contains(&v))
}

fn render(inventory: &Inventory, observations: &Observations, now: u64) -> Result<String> {
    if inventory.schema_version != 1
        || observations.schema_version != 1
        || !(1..=86_400).contains(&inventory.valid_for_seconds)
        || inventory.boots.len() > TARGET_LIMIT
        || inventory.enrollments.len() > TARGET_LIMIT
        || observations.boots.len() > TARGET_LIMIT * 4
    {
        return Err("invalid reconciliation schema or limit".into());
    }
    let mut names = BTreeSet::new();
    for boot in &inventory.boots {
        if !reference(&boot.target)
            || !reference(&boot.boot_id)
            || boot.requested_at_ms > boot.deadline_ms
            || boot.requested_at_ms > inventory.updated_at_ms
            || !names.insert((&boot.target, &boot.boot_id))
        {
            return Err("invalid expected boot".into());
        }
    }
    if observations.boots.iter().any(|boot| {
        !reference(&boot.target)
            || !reference(&boot.boot_id)
            || boot.observed_at_ms > observations.updated_at_ms
    }) {
        return Err("invalid boot observation".into());
    }
    let inventory_fresh = fresh(inventory.updated_at_ms, now, inventory.valid_for_seconds);
    let observations_fresh = fresh(observations.updated_at_ms, now, inventory.valid_for_seconds);
    let mut states = [0u64; 6];
    for expected in &inventory.boots {
        let state = if !inventory_fresh || !observations_fresh {
            4
        } else {
            let latest = observations
                .boots
                .iter()
                .filter(|value| {
                    value.target == expected.target
                        && value.boot_id == expected.boot_id
                        && value.observed_at_ms >= expected.requested_at_ms
                })
                .max_by_key(|value| value.observed_at_ms);
            match latest {
                Some(latest)
                    if observations.boots.iter().any(|value| {
                        value.target == expected.target
                            && value.boot_id == expected.boot_id
                            && value.observed_at_ms == latest.observed_at_ms
                            && value.outcome != latest.outcome
                    }) =>
                {
                    4
                }
                Some(value)
                    if value.outcome == BootOutcome::Success
                        && value.observed_at_ms > expected.deadline_ms =>
                {
                    5
                }
                Some(value) if value.outcome == BootOutcome::Success => 0,
                Some(_) => 1,
                None if now <= expected.deadline_ms => 2,
                None => 3,
            }
        };
        states[state] += 1;
    }
    let mut pending = 0;
    let mut unknown = 0;
    let mut awaiting_boot_test = 0;
    let mut oldest = None;
    let mut oldest_pending = None;
    let mut oldest_awaiting = None;
    let mut oldest_unknown = None;
    let mut journals = BTreeSet::new();
    let mut journal_files = BTreeSet::new();
    for enrollment in &inventory.enrollments {
        if !journals.insert(&enrollment.journal)
            || enrollment.created_at_ms > now
            || enrollment.created_at_ms > inventory.updated_at_ms
        {
            return Err("invalid enrollment inventory".into());
        }
        if !inventory_fresh {
            unknown += 1;
            older(&mut oldest_unknown, enrollment.created_at_ms);
            older(&mut oldest, enrollment.created_at_ms);
            continue;
        }
        let state = match read_held(&enrollment.journal, JOURNAL_LIMIT) {
            Ok((bytes, identity)) => {
                if !journal_files.insert(identity) {
                    return Err("duplicate journal file".into());
                }
                journal_committed(&bytes)
            }
            Err(_) => None,
        };
        match state {
            Some(true) if !enrollment.production_boot_test_passed => {
                awaiting_boot_test += 1;
                older(&mut oldest_awaiting, enrollment.created_at_ms);
                older(&mut oldest, enrollment.created_at_ms);
            }
            Some(true) => {}
            Some(false) => {
                pending += 1;
                older(&mut oldest_pending, enrollment.created_at_ms);
                older(&mut oldest, enrollment.created_at_ms);
            }
            None => {
                unknown += 1;
                older(&mut oldest_unknown, enrollment.created_at_ms);
                older(&mut oldest, enrollment.created_at_ms);
            }
        }
    }
    let mut result = String::new();
    use std::fmt::Write as _;
    for (state, count) in [
        "success",
        "failure",
        "pending",
        "missing",
        "unknown",
        "late_success",
    ]
    .into_iter()
    .zip(states)
    {
        let _ = writeln!(result, "leelo_boot_targets{{state=\"{state}\"}} {count}");
    }
    let _ = writeln!(
        result,
        "leelo_inventory_fresh {}\nleelo_boot_observations_fresh {}\nleelo_reconciliation_snapshot_timestamp_seconds {}\nleelo_enrollments_requiring_reconciliation {pending}\nleelo_enrollments_unknown {unknown}\nleelo_enrollments_awaiting_boot_test {awaiting_boot_test}\nleelo_oldest_unresolved_enrollment_timestamp_seconds {}\nleelo_oldest_enrollment_requiring_reconciliation_timestamp_seconds {}\nleelo_oldest_enrollment_awaiting_boot_test_timestamp_seconds {}\nleelo_oldest_unknown_enrollment_timestamp_seconds {}",
        u8::from(inventory_fresh),
        u8::from(observations_fresh),
        now as f64 / 1000.0,
        oldest.unwrap_or(0) as f64 / 1000.0,
        oldest_pending.unwrap_or(0) as f64 / 1000.0,
        oldest_awaiting.unwrap_or(0) as f64 / 1000.0,
        oldest_unknown.unwrap_or(0) as f64 / 1000.0
    );
    Ok(result)
}

fn older(current: &mut Option<u64>, timestamp: u64) {
    *current = Some(current.map_or(timestamp, |previous| previous.min(timestamp)));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityRecord {
    phase: String,
    binding_id: String,
    volume_uuid: String,
    slot: u8,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleRecord {
    phase: String,
    path: PathBuf,
    sha384: String,
}

fn lower_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut bytes = [0; N];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] =
            (char::from(chunk[0]).to_digit(16)? * 16 + char::from(chunk[1]).to_digit(16)?) as u8;
    }
    Some(bytes)
}

fn journal_identity(record: &IdentityRecord) -> Option<([u8; 32], [u8; 16], u8)> {
    let binding = lower_hex::<32>(&record.binding_id)?;
    if record.volume_uuid.len() != 36
        || [8, 13, 18, 23]
            .iter()
            .any(|&index| record.volume_uuid.as_bytes()[index] != b'-')
    {
        return None;
    }
    let volume = lower_hex::<16>(&record.volume_uuid.replace('-', ""))?;
    if binding == [0; 32] || volume == [0; 16] || record.slot >= 32 {
        return None;
    }
    Some((binding, volume, record.slot))
}

/// Validate the CLI's exact record sequence, including stable local identities. These
/// fields never leave the reader. Prior observations do not prove current disk state.
fn journal_committed(bytes: &[u8]) -> Option<bool> {
    if bytes.is_empty() || !bytes.ends_with(b"\n") || bytes.len() > JOURNAL_LIMIT {
        return None;
    }
    let phases = [
        "preflight",
        "pending-bundle-durable",
        "prepared-and-recovery-tested",
        "token-written-and-slot-tested",
    ];
    let mut identity = None;
    let mut committed = false;
    for (count, line) in bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        if line.len() > 8192 {
            return None;
        }
        let phase = *phases.get(count)?;
        if count == 1 {
            let record: BundleRecord = serde_json::from_slice(line).ok()?;
            if record.phase != phase
                || record.path.as_os_str().is_empty()
                || lower_hex::<48>(&record.sha384).is_none()
            {
                return None;
            }
        } else {
            let record: IdentityRecord = serde_json::from_slice(line).ok()?;
            if record.phase != phase {
                return None;
            }
            let observed = journal_identity(&record)?;
            if identity.is_some_and(|previous| previous != observed) {
                return None;
            }
            identity = Some(observed);
        }
        committed = count == phases.len() - 1;
    }
    Some(committed)
}

pub fn run(inventory: &Path, observations: &Path, output: &Path) -> Result<()> {
    let inventory: Inventory = serde_json::from_slice(&read_bounded(inventory)?)?;
    let observations: Observations = serde_json::from_slice(&read_bounded(observations)?)?;
    let now = leelo_telemetry::unix_time_ms().ok_or("clock unavailable")?;
    atomic_write(output, render(&inventory, &observations, now)?.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inventory() -> Inventory {
        Inventory {
            schema_version: 1,
            updated_at_ms: 10_000,
            valid_for_seconds: 30,
            boots: vec![ExpectedBoot {
                target: "critical_service".into(),
                boot_id: "boot_new".into(),
                requested_at_ms: 1000,
                deadline_ms: 9000,
            }],
            enrollments: Vec::new(),
        }
    }

    #[test]
    fn absent_and_stale_hosts_never_become_success() {
        let mut inventory = inventory();
        let mut observations = Observations {
            schema_version: 1,
            updated_at_ms: 10_000,
            boots: vec![],
        };
        assert!(
            render(&inventory, &observations, 10_000)
                .unwrap()
                .contains("state=\"missing\"} 1")
        );
        observations.boots.push(BootObservation {
            target: "critical_service".into(),
            boot_id: "boot_old".into(),
            observed_at_ms: 5000,
            outcome: BootOutcome::Success,
        });
        assert!(
            render(&inventory, &observations, 10_000)
                .unwrap()
                .contains("state=\"missing\"} 1")
        );
        observations.boots[0].boot_id = "boot_new".into();
        assert!(
            render(&inventory, &observations, 10_000)
                .unwrap()
                .contains("state=\"success\"} 1")
        );
        inventory.updated_at_ms = 2000;
        assert!(
            render(&inventory, &observations, 50_000)
                .unwrap()
                .contains("state=\"unknown\"} 1")
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn unfinished_journal_requires_reconciliation_even_after_command_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enrollment.jsonl");
        std::fs::write(&path, journal_bytes(3)).unwrap();
        let mut inventory = inventory();
        inventory.enrollments.push(Enrollment {
            journal: path.clone(),
            created_at_ms: 1000,
            production_boot_test_passed: false,
        });
        let observations = Observations {
            schema_version: 1,
            updated_at_ms: 10_000,
            boots: vec![],
        };
        let text = render(&inventory, &observations, 10_000).unwrap();
        assert!(text.contains("leelo_enrollments_requiring_reconciliation 1"));
        assert!(!text.contains("enrollment.jsonl"));
        std::fs::write(&path, journal_bytes(4)).unwrap();
        assert!(
            render(&inventory, &observations, 10_000)
                .unwrap()
                .contains("leelo_enrollments_awaiting_boot_test 1")
        );
        std::fs::write(&path, "{\"phase\":").unwrap();
        assert!(
            render(&inventory, &observations, 10_000)
                .unwrap()
                .contains("leelo_enrollments_unknown 1")
        );
    }

    fn journal_bytes(count: usize) -> Vec<u8> {
        let identity = |phase| {
            serde_json::json!({
                "phase":phase, "binding_id":"11".repeat(32),
                "volume_uuid":"11111111-1111-1111-1111-111111111111", "slot":1,
            })
        };
        let lines = [
            identity("preflight"),
            serde_json::json!({
                "phase":"pending-bundle-durable", "path":"/private/enrollment.pending.leelo", "sha384":"22".repeat(48),
            }),
            identity("prepared-and-recovery-tested"),
            identity("token-written-and-slot-tested"),
        ];
        let mut bytes = Vec::new();
        for line in &lines[..count] {
            bytes.extend(serde_json::to_vec(line).unwrap());
            bytes.push(b'\n');
        }
        bytes
    }

    fn observations(boots: Vec<BootObservation>) -> Observations {
        Observations {
            schema_version: 1,
            updated_at_ms: 10_000,
            boots,
        }
    }
    fn boot(observed_at_ms: u64, outcome: BootOutcome) -> BootObservation {
        BootObservation {
            target: "critical_service".into(),
            boot_id: "boot_new".into(),
            observed_at_ms,
            outcome,
        }
    }

    #[test]
    fn conflicting_ties_are_unknown_independent_of_input_order() {
        for outcomes in [
            [BootOutcome::Success, BootOutcome::Failure],
            [BootOutcome::Failure, BootOutcome::Success],
        ] {
            let observed = observations(
                outcomes
                    .into_iter()
                    .map(|outcome| boot(5000, outcome))
                    .collect(),
            );
            let text = render(&inventory(), &observed, 10_000).unwrap();
            assert!(text.contains("state=\"unknown\"} 1"));
            assert!(text.contains("state=\"success\"} 0"));
        }
        let observed = observations(vec![
            boot(5000, BootOutcome::Success),
            boot(5000, BootOutcome::Success),
            boot(3000, BootOutcome::Failure),
        ]);
        assert!(
            render(&inventory(), &observed, 10_000)
                .unwrap()
                .contains("state=\"success\"} 1")
        );
    }

    #[test]
    fn late_activation_is_distinct_from_late_delivery_of_timely_success() {
        let late = observations(vec![boot(9500, BootOutcome::Success)]);
        let text = render(&inventory(), &late, 10_000).unwrap();
        assert!(text.contains("state=\"late_success\"} 1"));
        assert!(text.contains("state=\"success\"} 0"));
        let timely = observations(vec![boot(8500, BootOutcome::Success)]);
        assert!(
            render(&inventory(), &timely, 10_000)
                .unwrap()
                .contains("state=\"success\"} 1")
        );
    }

    #[test]
    fn future_or_stale_snapshots_never_supply_success() {
        let mut observed = observations(vec![boot(8500, BootOutcome::Success)]);
        observed.updated_at_ms = 10_001;
        assert!(
            render(&inventory(), &observed, 10_000)
                .unwrap()
                .contains("state=\"unknown\"} 1")
        );
        observed.updated_at_ms = 10_000;
        assert!(
            render(&inventory(), &observed, 50_000)
                .unwrap()
                .contains("state=\"unknown\"} 1")
        );
    }

    #[test]
    fn journals_require_real_record_shape_order_and_consistent_private_identity() {
        for count in 1..=3 {
            assert_eq!(journal_committed(&journal_bytes(count)), Some(false));
        }
        assert_eq!(journal_committed(&journal_bytes(4)), Some(true));
        assert_eq!(journal_committed(b""), None);
        assert_eq!(
            journal_committed(b"{\"phase\":\"token-written-and-slot-tested\"}\n"),
            None
        );
        let mut complete = journal_bytes(4);
        complete.pop();
        assert_eq!(journal_committed(&complete), None);
        let text = String::from_utf8(journal_bytes(4)).unwrap();
        let changed = text.replacen("\"slot\":1", "\"slot\":2", 1);
        assert_eq!(journal_committed(changed.as_bytes()), None);
        let bad_hash = text.replace(&"22".repeat(48), "incorrect");
        assert_eq!(journal_committed(bad_hash.as_bytes()), None);
        let mut lines: Vec<_> = text.lines().collect();
        lines.swap(1, 2);
        assert_eq!(
            journal_committed(format!("{}\n", lines.join("\n")).as_bytes()),
            None
        );
        let extra_field = text.replacen("\"slot\":1", "\"slot\":1,\"unexpected\":true", 1);
        assert_eq!(journal_committed(extra_field.as_bytes()), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enrollment_ages_are_specific_to_their_reconciliation_state() {
        let dir = tempfile::tempdir().unwrap();
        let pending = dir.path().join("pending.journal");
        let committed = dir.path().join("committed.journal");
        std::fs::write(&pending, journal_bytes(3)).unwrap();
        std::fs::write(&committed, journal_bytes(4)).unwrap();
        let mut inventory = inventory();
        inventory.enrollments = vec![
            Enrollment {
                journal: pending,
                created_at_ms: 3000,
                production_boot_test_passed: false,
            },
            Enrollment {
                journal: committed,
                created_at_ms: 2000,
                production_boot_test_passed: false,
            },
            Enrollment {
                journal: dir.path().join("missing.journal"),
                created_at_ms: 500,
                production_boot_test_passed: false,
            },
        ];
        let text = render(&inventory, &observations(vec![]), 10_000).unwrap();
        assert!(text.contains("leelo_enrollments_requiring_reconciliation 1\n"));
        assert!(text.contains("leelo_enrollments_unknown 1\n"));
        assert!(text.contains("leelo_enrollments_awaiting_boot_test 1\n"));
        assert!(text.contains("leelo_oldest_unresolved_enrollment_timestamp_seconds 0.5\n"));
        assert!(
            text.contains("leelo_oldest_enrollment_requiring_reconciliation_timestamp_seconds 3\n")
        );
        assert!(text.contains("leelo_oldest_enrollment_awaiting_boot_test_timestamp_seconds 2\n"));
        assert!(text.contains("leelo_oldest_unknown_enrollment_timestamp_seconds 0.5\n"));
        let stale = render(&inventory, &observations(vec![]), 50_000).unwrap();
        assert!(stale.contains("leelo_enrollments_unknown 3\n"));
        assert!(
            stale
                .contains("leelo_oldest_enrollment_requiring_reconciliation_timestamp_seconds 0\n")
        );
        assert!(stale.contains("leelo_oldest_unknown_enrollment_timestamp_seconds 0.5\n"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_reader_rejects_symlinks_fifos_writable_files_and_oversize() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        std::fs::write(&path, journal_bytes(4)).unwrap();
        assert!(read_held(&path, JOURNAL_LIMIT).is_ok());
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_held(&link, JOURNAL_LIMIT).is_err());
        let fifo = dir.path().join("fifo");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        let started = std::time::Instant::now();
        assert!(read_held(&fifo, JOURNAL_LIMIT).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_held(&path, JOURNAL_LIMIT).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len((JOURNAL_LIMIT + 1) as u64)
            .unwrap();
        assert!(read_held(&path, JOURNAL_LIMIT).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn journal_aliases_cannot_duplicate_the_enrollment_denominator() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let alias = dir.path().join("alias");
        std::fs::write(&path, journal_bytes(4)).unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        let mut inventory = inventory();
        inventory.enrollments = vec![
            Enrollment {
                journal: path,
                created_at_ms: 1000,
                production_boot_test_passed: false,
            },
            Enrollment {
                journal: alias,
                created_at_ms: 1000,
                production_boot_test_passed: false,
            },
        ];
        assert!(render(&inventory, &observations(vec![]), 10_000).is_err());
    }
}
