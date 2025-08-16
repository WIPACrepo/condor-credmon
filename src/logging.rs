use std::error::Error;

use log4rs::{
    Handle,
    append::{
        console::{ConsoleAppender, Target},
        rolling_file::policy::compound::{CompoundPolicy, roll::fixed_window::FixedWindowRoller, trigger::size::SizeTrigger},
    },
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};

use crate::config::{coerce_to_int, config as condor_config};

const LOG_DEFAULT_LEVEL: log::LevelFilter = log::LevelFilter::Warn;
const LOG_DEFAULT_SIZE: u64 = 1000000000;
const LOG_DEFAULT_ROTATIONS: u32 = 5;
const LOG_DEFAULT_PATH: &str = "/var/log/condor/CredMonOAuthLog";

fn get_size(key: &str) -> u64 {
    let config = condor_config();
    match config.get(key) {
        Some(x) => match x.as_str() {
            Some(y) => {
                if let Some(z) = y.strip_suffix("Kb") {
                    z.parse::<u64>().unwrap_or(LOG_DEFAULT_SIZE / 1000000) * 1000000
                } else if let Some(z) = y.strip_suffix("Mb") {
                    z.parse::<u64>().unwrap_or(LOG_DEFAULT_SIZE / 1000) * 1000
                } else if let Some(z) = y.strip_suffix("Gb") {
                    z.parse::<u64>().unwrap_or(LOG_DEFAULT_SIZE / 1000000000) * 1000000000
                } else {
                    y.parse::<u64>().unwrap_or(LOG_DEFAULT_SIZE)
                }
            }
            None => match x.as_u64() {
                Some(y) => y,
                None => LOG_DEFAULT_SIZE,
            },
        },
        None => LOG_DEFAULT_SIZE,
    }
}

fn log_to_file(log_verbosity: log::LevelFilter) -> Result<log4rs::Handle, Box<dyn Error>> {
    let config = condor_config();

    let log_size = get_size("MAX_CREDMON_OAUTH_LOG");

    let log_rotations = match config.get("MAX_NUM_CREDMON_OAUTH_LOG") {
        Some(x) => match coerce_to_int(x) {
            Ok(x) => x as u32,
            _ => LOG_DEFAULT_ROTATIONS,
        },
        None => LOG_DEFAULT_ROTATIONS,
    };

    let log_path = match config.get("CREDMON_OAUTH_LOG") {
        Some(x) => match x.as_str() {
            Some(y) => y,
            None => LOG_DEFAULT_PATH,
        },
        None => LOG_DEFAULT_PATH,
    };
    let rotate_log_path = log_path.to_owned() + ".{}";

    // Create a policy to use with the file logging
    let trigger = SizeTrigger::new(log_size);
    let roller = FixedWindowRoller::builder().build(rotate_log_path.as_str(), log_rotations)?;
    let policy = CompoundPolicy::new(Box::new(trigger), Box::new(roller));

    // Logging to log file (with rolling)
    let logfile = log4rs::append::rolling_file::RollingFileAppender::builder()
        // Pattern: https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html
        .encoder(Box::new(PatternEncoder::new("{d} {l} {M:<24} - {m}{n}")))
        .build(log_path, Box::new(policy))?;

    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(Root::builder().appender("logfile").build(log_verbosity))?;

    let handle = log4rs::init_config(config)?;
    Ok(handle)
}

fn log_to_stderr(log_verbosity: log::LevelFilter) -> Result<log4rs::Handle, Box<dyn Error>> {
    // Build a stderr logger.
    let stderr = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d} {l} {M:<24} - {m}{n}")))
        .target(Target::Stderr)
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stderr", Box::new(stderr)))
        .build(Root::builder().appender("stderr").build(log_verbosity))
        .unwrap();

    let handle = log4rs::init_config(config)?;
    Ok(handle)
}

fn get_log_level(config: &crate::config::Config) -> log::LevelFilter {
    match config.get("CREDMON_OAUTH_DEBUG") {
        Some(x) => match x.as_str() {
            Some("D_ALWAYS") => log::LevelFilter::Warn,
            Some("D_FULLDEBUG") => log::LevelFilter::Info,
            Some("D_ALL") | Some("D_ANY") => log::LevelFilter::Debug,
            _ => LOG_DEFAULT_LEVEL,
        },
        None => LOG_DEFAULT_LEVEL,
    }
}

pub fn configure_logging(how_output: Option<&str>) -> Result<log4rs::Handle, Box<dyn Error>> {
    let config = condor_config();

    let log_verbosity = get_log_level(&config);

    match how_output {
        Some("stderr") => log_to_stderr(log_verbosity),
        _ => log_to_file(log_verbosity),
    }
}

pub fn update_file_logging(handle: &mut Handle) {
    let config = condor_config();

    let log_verbosity = get_log_level(&config);

    // Build a stderr logger.
    let stderr = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d} {l} {M} - {m}{n}")))
        .target(Target::Stderr)
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stderr", Box::new(stderr)))
        .build(Root::builder().appender("stderr").build(log_verbosity))
        .unwrap();

    handle.set_config(config);
}

static INIT: std::sync::Once = std::sync::Once::new();

pub fn test_logger() {
    INIT.call_once(|| {
        stderrlog::new().verbosity(log::Level::Debug).init().unwrap();
    });
}
