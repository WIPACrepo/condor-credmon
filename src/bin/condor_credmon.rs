use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::thread::sleep;
use std::{error::Error, thread, time::Duration};

use condor_credmon::config::reload_config;
use condor_credmon::refresh::refresh_all_tokens;

fn main() -> Result<(), Box<dyn Error>> {
    static RELOAD: AtomicBool = AtomicBool::new(false);
    let mut signals = Signals::new([SIGHUP])?;

    thread::spawn(move || {
        for sig in signals.forever() {
            println!("Received reload signal {:?}", sig);
            RELOAD.store(true, Relaxed);
        }
    });

    loop {
        refresh_all_tokens()?;

        sleep(Duration::from_secs(1));
        if RELOAD.load(Relaxed) {
            RELOAD.store(false, Relaxed);
            reload_config();
        }
    }
}
