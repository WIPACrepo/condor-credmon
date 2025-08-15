use log::warn;
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;
use std::backtrace::Backtrace;
use std::error::Error;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::thread;
use std::thread::sleep;
use std::time::Duration;

use condor_credmon::config::reload_config;
use condor_credmon::logging::configure_logging;
use condor_credmon::refresh::refresh_all_tokens;

fn run() -> Result<(), Box<dyn Error>> {
    let _log_handle = configure_logging(None)?;

    static RELOAD: AtomicBool = AtomicBool::new(false);
    let mut signals = Signals::new([SIGHUP])?;

    thread::spawn(move || {
        for sig in signals.forever() {
            warn!("Received reload signal {sig:?}");
            RELOAD.store(true, Relaxed);
        }
    });

    loop {
        log::info!("Checking for tokens to refresh");
        match refresh_all_tokens() {
            Ok(_) => {}
            Err(e) => warn!("Error refreshing: {e}"),
        };
        log::info!("Done refreshing tokens");

        sleep(Duration::from_secs(30));
        if RELOAD.load(Relaxed) {
            RELOAD.store(false, Relaxed);
            reload_config();
        }
    }
}

fn main() {
    match run() {
        Ok(_) => (),
        Err(e) => {
            log::error!("Backtrace: {}", Backtrace::force_capture());
            log::error!("Error creating token: {e}");
        }
    }
}
