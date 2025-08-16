use log::warn;
use serde_json::{Map, Value};
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;
use std::backtrace::Backtrace;
use std::error::Error;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::thread;
use std::thread::sleep;
use std::time::{Duration, SystemTime};

use condor_credmon::config::{coerce_to_int, config as condor_config, reload_config};
use condor_credmon::logging::{configure_logging, update_file_logging};
use condor_credmon::refresh::refresh_all_tokens;

const TOKEN_REFRESH_INTERVAL: u64 = 60;

fn get_refresh_interval(config: &Map<String, Value>) -> Result<u64, Box<dyn Error>> {
    match config.get("CREDMON_OAUTH_TOKEN_REFRESH") {
        Some(x) => coerce_to_int(x),
        None => match config.get("CREDMON_OAUTH_TOKEN_MINIMUM") {
            Some(x) => Ok(coerce_to_int(x)? / 2),
            None => Ok(TOKEN_REFRESH_INTERVAL),
        },
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut log_handle = configure_logging(None)?;

    static RELOAD: AtomicBool = AtomicBool::new(false);
    let mut signals = Signals::new([SIGHUP])?;

    thread::spawn(move || {
        for sig in signals.forever() {
            warn!("Received reload signal {sig:?}");
            RELOAD.store(true, Relaxed);
        }
    });

    let mut config = condor_config();
    let mut refresh_interval = get_refresh_interval(&config)?;
    let mut last_refresh = SystemTime::UNIX_EPOCH;

    loop {
        let now = SystemTime::now();
        if now.duration_since(last_refresh).unwrap().as_secs() > refresh_interval {
            log::info!("Checking for tokens to refresh");
            match refresh_all_tokens() {
                Ok(_) => {}
                Err(e) => warn!("Error refreshing: {e}"),
            };
            log::info!("Done refreshing tokens");
            last_refresh = now;
        }

        sleep(Duration::from_millis(100));
        if RELOAD.load(Relaxed) {
            RELOAD.store(false, Relaxed);
            reload_config();
            update_file_logging(&mut log_handle)?;
            config = condor_config();
            refresh_interval = get_refresh_interval(&config)?;
            last_refresh = SystemTime::UNIX_EPOCH; // refresh immediately after reload
        }
    }
}

fn main() {
    match run() {
        Ok(_) => (),
        Err(e) => {
            log::error!("Backtrace: {}", Backtrace::force_capture());
            log::error!("Fatal error in credmon: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use condor_credmon::logging::test_logger;

    #[test]
    fn test_get_refresh_interval() {
        test_logger();

        let mut config = Map::new();

        let ret = get_refresh_interval(&config).unwrap();
        assert_eq!(ret, TOKEN_REFRESH_INTERVAL);

        config.insert("CREDMON_OAUTH_TOKEN_MINIMUM".into(), 30.into());
        let ret = get_refresh_interval(&config).unwrap();
        assert_eq!(ret, 15);

        config.insert("CREDMON_OAUTH_TOKEN_REFRESH".into(), 10.into());
        let ret = get_refresh_interval(&config).unwrap();
        assert_eq!(ret, 10);
    }
}
