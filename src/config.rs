use memoize::memoize;
use serde_json::{Map, Value};
use std::process::Command;

static HTCONDOR_CONFIG: &str = "-c 'import htcondor,json; print(json.dumps({k:v for k,v in htcondor.param.items()}))'";

#[memoize]
pub fn config() -> Map<String, Value> {
    // Execute the Python script
    let output = Command::new("python3").arg(HTCONDOR_CONFIG).output().expect("Cannot get HTCondor config!");

    // Check if the command was successful
    if !output.status.success() {
        eprintln!("Python script failed: {:?}", output.stderr);
        panic!("Cannot get HTCondor config!");
    }

    // Convert stdout to a String
    let json_output = String::from_utf8(output.stdout).expect("Cannot decode HTCondor config!");
    serde_json::from_str(&json_output).expect("Cannot decode HTCondor config!")
}

pub fn reload_config() -> () {
    memoized_flush_config()
}
