use std::process::Command;

fn invalid_startup(overrides: &[(&str, &str)]) -> Result<String, String> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_backup-server"));
    command
        .arg("serve")
        .env_clear()
        .env("BACKUP_SERVER_AUTH_AUDIENCE", "https://backup.example.com")
        .env("BACKUP_SERVER_DB_PATH", "/tmp/unused-backup.sqlite3")
        .env("BACKUP_SERVER_MAX_LIVE_BYTES", "100000000000")
        .env("BACKUP_SERVER_MAX_HEADS", "90000")
        .env("BACKUP_SERVER_LIMITER_MAX_SUBJECTS", "10000");
    for (key, value) in overrides {
        command.env(key, value);
    }
    let output = command
        .output()
        .map_err(|_| "failed to run backup-server".to_owned())?;
    if output.status.success() {
        return Err("invalid configuration unexpectedly started".to_owned());
    }
    let mut bytes = output.stdout;
    bytes.extend_from_slice(&output.stderr);
    String::from_utf8(bytes).map_err(|_| "startup error was not UTF-8".to_owned())
}

#[test]
fn invalid_authentication_audience_fails_startup() -> Result<(), String> {
    let missing = invalid_startup(&[("BACKUP_SERVER_AUTH_AUDIENCE", "")])?;
    assert!(missing.contains("BACKUP_SERVER_AUTH_AUDIENCE is required"));

    let oversized = "x".repeat(256);
    let oversized = invalid_startup(&[("BACKUP_SERVER_AUTH_AUDIENCE", &oversized)])?;
    assert!(oversized.contains("must be at most 255 UTF-8 bytes"));
    Ok(())
}

#[test]
fn contradictory_size_and_concurrency_configuration_fails_startup() -> Result<(), String> {
    let oversized = invalid_startup(&[("BACKUP_SERVER_ACCEPTED_CIPHERTEXT_BYTES", "1048577")])?;
    assert!(oversized.contains("must be at most 1048576"));

    let undersized_body = invalid_startup(&[("BACKUP_SERVER_STORE_BODY_LIMIT_BYTES", "1398104")])?;
    assert!(undersized_body.contains("must be at least"));

    let queue_without_headroom = invalid_startup(&[
        ("BACKUP_SERVER_STORAGE_QUEUE_DEPTH", "36"),
        ("BACKUP_SERVER_FETCH_MAX_IN_FLIGHT", "24"),
        ("BACKUP_SERVER_STORE_MAX_IN_FLIGHT", "8"),
        ("BACKUP_SERVER_DELETE_MAX_IN_FLIGHT", "4"),
    ])?;
    assert!(queue_without_headroom.contains("must be greater than the sum"));

    let zero_overflow_retry = invalid_startup(&[("BACKUP_SERVER_OVERFLOW_RETRY_AFTER_SECS", "0")])?;
    assert!(zero_overflow_retry.contains("must be positive"));
    Ok(())
}

#[test]
fn contradictory_capacity_and_admission_configuration_fails_startup() -> Result<(), String> {
    let impossible_shape = invalid_startup(&[("BACKUP_SERVER_MAX_LIVE_BYTES", "94371839999")])?;
    assert!(impossible_shape.contains("must not exceed BACKUP_SERVER_MAX_LIVE_BYTES"));

    let undersized_growth_bucket = invalid_startup(&[(
        "BACKUP_SERVER_TOTAL_GROWTH_BUCKET_CAPACITY_BYTES",
        "1048575",
    )])?;
    assert!(undersized_growth_bucket.contains("must admit one maximum-size ciphertext"));

    let removed_variable = invalid_startup(&[(
        "BACKUP_SERVER_NEW_ALLOCATION_BUCKET_CAPACITY_BYTES",
        "100000000",
    )])?;
    assert!(removed_variable.contains("unknown configuration variable"));
    Ok(())
}
