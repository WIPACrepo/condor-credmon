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

use crate::config::{Config as ConfigType, coerce_to_int, config as condor_config};

const LOG_DEFAULT_LEVEL: log::LevelFilter = log::LevelFilter::Warn;
const LOG_DEFAULT_SIZE: u64 = 1000000000;
const LOG_DEFAULT_ROTATIONS: u32 = 5;
const LOG_DEFAULT_PATH: &str = "/var/log/condor/CredMonOAuthLog";
const LOG_FORMAT: &str = "{d(%Y-%m-%dT%H:%M:%S%.3f)} {l} {M:<24} - {m}{n}";

fn get_size(config: &ConfigType, key: &str) -> u64 {
    match config.get(key) {
        Some(x) => match x.as_str() {
            Some(y) => {
                if let Some(z) = y.strip_suffix("Kb") {
                    z.parse::<u64>().unwrap_or(LOG_DEFAULT_SIZE / 1000000) * 1000
                } else if let Some(z) = y.strip_suffix("Mb") {
                    z.parse::<u64>().unwrap_or(LOG_DEFAULT_SIZE / 1000) * 1000000
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

fn log_to_file_setup(condor_config: &ConfigType) -> Result<Config, Box<dyn Error>> {
    let log_size = get_size(condor_config, "MAX_CREDMON_OAUTH_LOG");
    let log_verbosity = get_log_level(condor_config);

    let log_rotations = match condor_config.get("MAX_NUM_CREDMON_OAUTH_LOG") {
        Some(x) => match coerce_to_int(x) {
            Ok(x) => x as u32,
            _ => LOG_DEFAULT_ROTATIONS,
        },
        None => LOG_DEFAULT_ROTATIONS,
    };

    let log_path = match condor_config.get("CREDMON_OAUTH_LOG") {
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
        .encoder(Box::new(PatternEncoder::new(LOG_FORMAT)))
        .build(log_path, Box::new(policy))?;

    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(Root::builder().appender("logfile").build(log_verbosity))?;

    Ok(config)
}

fn log_to_file(condor_config: &ConfigType) -> Result<log4rs::Handle, Box<dyn Error>> {
    let config = log_to_file_setup(condor_config)?;
    let handle = log4rs::init_config(config)?;
    Ok(handle)
}

fn log_to_stderr(condor_config: &ConfigType) -> Result<log4rs::Handle, Box<dyn Error>> {
    let log_verbosity = get_log_level(condor_config);

    // Build a stderr logger.
    let stderr = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(LOG_FORMAT)))
        .target(Target::Stderr)
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stderr", Box::new(stderr)))
        .build(Root::builder().appender("stderr").build(log_verbosity))
        .unwrap();

    let handle = log4rs::init_config(config)?;
    Ok(handle)
}

pub fn configure_logging(how_output: Option<&str>) -> Result<log4rs::Handle, Box<dyn Error>> {
    let config = condor_config();

    match how_output {
        Some("stderr") => log_to_stderr(&config),
        _ => log_to_file(&config),
    }
}

pub fn update_file_logging(handle: &mut Handle) -> Result<(), Box<dyn Error>> {
    let config = condor_config();
    handle.set_config(log_to_file_setup(&config)?);
    Ok(())
}

static INIT: std::sync::Once = std::sync::Once::new();

pub fn test_logger() {
    INIT.call_once(|| {
        stderrlog::new().verbosity(log::Level::Debug).init().unwrap();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_get_size() {
        test_logger();

        let mut config = ConfigType::new();
        config.insert("test".into(), 100.into());

        assert_eq!(get_size(&config, "test"), 100);

        config.insert("test2".into(), "100".into());
        assert_eq!(get_size(&config, "test2"), 100);

        config.insert("test3".into(), "10Kb".into());
        assert_eq!(get_size(&config, "test3"), 10000);

        config.insert("test4".into(), "10Mb".into());
        assert_eq!(get_size(&config, "test4"), 10000000);

        config.insert("test5".into(), "1Gb".into());
        assert_eq!(get_size(&config, "test5"), 1000000000);

        assert_eq!(get_size(&config, "none"), LOG_DEFAULT_SIZE);
    }

    #[test]
    fn test_get_level() {
        test_logger();

        let mut config = ConfigType::new();

        assert_eq!(get_log_level(&config), LOG_DEFAULT_LEVEL);

        config.insert("CREDMON_OAUTH_DEBUG".into(), "D_ALWAYS".into());
        assert_eq!(get_log_level(&config), log::LevelFilter::Warn);

        config.insert("CREDMON_OAUTH_DEBUG".into(), "D_FULLDEBUG".into());
        assert_eq!(get_log_level(&config), log::LevelFilter::Info);

        config.insert("CREDMON_OAUTH_DEBUG".into(), "D_ANY".into());
        assert_eq!(get_log_level(&config), log::LevelFilter::Debug);
    }

    #[test]
    fn test_log_to_file_setup() {
        test_logger();

        let tmp_dir = tempdir().unwrap();
        let log_path = tmp_dir.path().join("tmp_logfile");

        let mut config = ConfigType::new();
        config.insert("CREDMON_OAUTH_LOG".into(), log_path.to_str().unwrap().into());

        let ret = match log_to_file_setup(&config) {
            Err(e) => {
                panic!("Error: {e}");
            }
            Ok(ret) => ret,
        };
        assert_eq!(ret.appenders().len(), 1);
    }

    #[test]
    fn test_errlog() {
        let config = ConfigType::new();
        log_to_stderr(&config).unwrap();
        log::error!("test");
    }
}
