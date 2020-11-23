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

    assert_errors(cmd, vec![
        "The following required arguments were not provided:",
        "<string>",
        "--function <function>",
    ]);

    Ok(())
}

#[test]
fn invalid_hash_function() -> Result<(), Box<dyn Error>> {
    let cmd = setup(vec!["Hello, world!", "-f", "foo"])?;

    assert_errors(cmd, vec!["invalid hash function: `foo`"]);

    Ok(())
}

#[test]
fn sha1_hex_test() -> Result<(), Box<dyn Error>> {
    let cmd = setup(vec!["Hello, world!", "-f", "sha1"])?;

    assert_success(cmd, vec!["943a702d06f34599aee1f8da8ef9f7296031d699"]);

    Ok(())
}

#[test]
fn sha1_bytes_test() -> Result<(), Box<dyn Error>> {
    let cmd = setup(vec!["Hello, world!", "-bf", "sha1"])?;

    assert_success(cmd, vec!["[148, 58, 112, 45, 6, 243, 69, 153, 174, 225, 248, 218, 142, 249, 247, 41, 96, 49, 214, 153]"]);

    Ok(())
}
