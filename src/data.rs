use serde::{Deserialize, Serialize};
use serde_json;
use std::io::BufReader;
use std::path::Path;
use std::{fs::File, io::Write};

#[derive(Serialize, Deserialize)]
pub struct RefreshFile {
    pub refresh_token: String,
    pub scopes: String,
}

impl RefreshFile {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let data = serde_json::from_reader(reader)?;
        Ok(data)
    }

    pub fn write_to_file<P: AsRef<Path>>(self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let json_string = serde_json::to_string_pretty(&self)?;
        let mut file = File::create(path)?;
        file.write_all(json_string.as_bytes())?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct AccessFile {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub expires_at: f64,
    pub scope: Vec<String>,
}

impl AccessFile {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let data = serde_json::from_reader(reader)?;
        Ok(data)
    }

    pub fn write_to_file<P: AsRef<Path>>(self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let json_string = serde_json::to_string_pretty(&self)?;
        let mut file = File::create(path)?;
        file.write_all(json_string.as_bytes())?;
        Ok(())
    }
}
