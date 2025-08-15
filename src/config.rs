use memoize::memoize;
use serde_json::{Map, Value};
use std::process::Command;

use crate::error::CredmonError;

static HTCONDOR_CONFIG: [&str; 2] = ["-c", "import htcondor,json; print(json.dumps({k:v for k,v in htcondor.param.items()}))"];

pub type Config = Map<String, Value>;

pub fn coerce_to_int(val: &Value) -> Result<u64, Box<dyn std::error::Error>> {
    match val.as_u64() {
        Some(x) => Ok(x),
        None => match val.as_str() {
            Some(x) => Ok(x.parse::<u64>()?),
            None => Err(Box::new(CredmonError::ConfigError("not an integer".into()))),
        },
    }
}

#[memoize]
pub fn config() -> Config {
    log::info!(target:"config", "Loading HTCondor config");

    // Execute the Python script
    let output = Command::new("python3").args(HTCONDOR_CONFIG).output().expect("Cannot get HTCondor config!");

    // Check if the command was successful
    if !output.status.success() {
        let err = String::from_utf8(output.stderr).expect("cannot decode stderr");
        log::error!(target: "config", "Python script failed: {err}");
        panic!("Cannot get HTCondor config!");
    }

    // Convert stdout to a String
    let json_output = String::from_utf8(output.stdout).expect("Cannot decode HTCondor config!");
    serde_json::from_str(&json_output).expect("Cannot decode HTCondor config!")
}

pub fn reload_config() {
    memoized_flush_config()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coerce_to_int() {
        let mut config: Map<String, Value> = Map::new();
        config.insert("foo".into(), "10".into());
        config.insert("bar".into(), 20.into());
        config.insert("baz".into(), "10Mb".into());

        assert_eq!(coerce_to_int(config.get("foo").unwrap()).unwrap(), 10);
        assert_eq!(coerce_to_int(config.get("bar").unwrap()).unwrap(), 20);
        assert!(coerce_to_int(config.get("baz").unwrap()).is_err());
    }
}
