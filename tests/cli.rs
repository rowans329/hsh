// Std imports
use std::error::Error;

// External imports
use assert_cmd::Command;
use predicates::prelude::*;

fn setup(args: Vec<&'static str>) -> Result<Command, Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("hsh")?;

    cmd.args(args);

    Ok(cmd)
}

fn assert_errors(mut cmd: Command, patterns: Vec<&'static str>) {
    let mut cmd = cmd.assert().failure();

    for pattern in patterns.iter() {
        let predicate = predicate::str::contains(*pattern);
        cmd = cmd.stderr(predicate);
    }
}

fn assert_success(mut cmd: Command, patterns: Vec<&str>) {
    let mut cmd = cmd.assert().success();

    for pattern in patterns.iter() {
        let predicate = predicate::str::contains(*pattern);
        cmd = cmd.stdout(predicate);
    }
}

#[test]
fn missing_args() -> Result<(), Box<dyn Error>> {
    let cmd = setup(vec![])?;

    assert_errors(
        cmd,
        vec![
            "The following required arguments were not provided:",
            "<string>",
            "<function>",
        ],
    );

    Ok(())
}

#[test]
fn invalid_hash_function() -> Result<(), Box<dyn Error>> {
    let cmd = setup(vec!["Hello, world!", "foo"])?;

    assert_errors(cmd, vec!["'foo' isn't a valid value for '<function>'"]);

    Ok(())
}

#[test]
fn sha1_hex_test() -> Result<(), Box<dyn Error>> {
    let cmd = setup(vec!["Hello, world!", "sha1"])?;

    assert_success(cmd, vec!["943a702d06f34599aee1f8da8ef9f7296031d699"]);

    Ok(())
}

#[test]
fn missing_bcrypt_inputs() -> Result<(), Box<dyn Error>> {
    let cmd = setup(vec!["Hello, world!", "bcrypt"])?;

    assert_errors(
        cmd,
        vec![
            "The following required arguments were not provided:",
            "--cost <cost>",
        ],
    );

    Ok(())
}

#[test]
fn missing_bcrypt_salt() -> Result<(), Box<dyn Error>> {
    let cmd = setup(vec!["Hello, world!", "bcrypt", "-c", "1"])?;

    assert_errors(
        cmd,
        vec![
            "The following required arguments were not provided:",
            "--salt <salt>",
        ],
    );

    Ok(())
}

#[test]
fn bcrypt_invalid_salt_hex_odd_digits() -> Result<(), Box<dyn Error>> {
    let cmd = setup(vec!["Hello, world!", "bcrypt", "-c", "1", "-s", "1a54e"])?;

    assert_errors(cmd, vec!["hex must have even length"]);

    Ok(())
}

#[test]
fn bcrypt_invalid_salt_incorrect_length_short() -> Result<(), Box<dyn Error>> {
    let cmd = setup(vec![
        "Hello, world!",
        "bcrypt",
        "-c",
        "1",
        "-s",
        "000102030405",
    ])?;

    assert_errors(
        cmd,
        vec!["incorrect salt length (expected 16 bytes, found 6)"],
    );

    Ok(())
}

#[test]
fn bcrypt_invalid_salt_incorrect_length_long() -> Result<(), Box<dyn Error>> {
    let cmd = setup(vec![
        "Hello, world!",
        "bcrypt",
        "-c",
        "1",
        "-s",
        "000102030405060708090a0b0c0d0e0f111213141516",
    ])?;

    assert_errors(
        cmd,
        vec!["incorrect salt length (expected 16 bytes, found 22)"],
    );

    Ok(())
}

#[test]
fn bcrypt_hex_test() -> Result<(), Box<dyn Error>> {
    let cmd = setup(vec![
        "Hello, world!",
        "bcrypt",
        "-c",
        "1",
        "-s",
        "000102030405060708090a0b0c0d0e0f",
    ])?;

    assert_success(
        cmd,
        vec!["0e96480b69ed820d168679047ec1625d334fc586df53823e"],
    );

    Ok(())
}
