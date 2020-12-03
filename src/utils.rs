// Std imports
use std::fmt::Arguments;

// External imports
use atty::Stream;
use chrono::Local;
use fern::{
    colors::{Color, ColoredLevelConfig, WithFgColor},
    Dispatch, FormatCallback,
};
use log::{Level, LevelFilter, Record};

pub fn parse_verbosity(v: u64) -> LevelFilter {
    match v {
        0 => LevelFilter::Off,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

pub fn setup_logger(log_level: LevelFilter) -> Result<(), fern::InitError> {
    Dispatch::new()
        .chain(
            Dispatch::new()
                .format(format_error_log)
                .level(LevelFilter::Error)
                .chain(std::io::stderr()),
        )
        .chain(
            Dispatch::new()
                .filter(|metadata| metadata.level() != LevelFilter::Error)
                .format(format_log)
                .level(log_level)
                .chain(std::io::stdout()),
        )
        .apply()?;
    Ok(())
}

fn format_log(out: FormatCallback, message: &Arguments, record: &Record) {
    if color_enabled() {
        out.finish(format_args!(
            "{}[{}][{}] {}",
            Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
            record.target(),
            color_level(record.level()),
            message,
        ))
    } else {
        out.finish(format_args!(
            "{}[{}][{}] {}",
            Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
            record.target(),
            record.level(),
            message,
        ))
    }
}

fn format_error_log(out: FormatCallback, message: &Arguments, record: &Record) {
    if color_enabled() {
        out.finish(format_args!(
            "[{}] {}",
            color_level(record.level()),
            message,
        ))
    } else {
        out.finish(format_args!("[{}] {}", record.level(), message))
    }
}

fn color_level(level: Level) -> WithFgColor<Level> {
    ColoredLevelConfig::new()
        .warn(Color::Yellow)
        .info(Color::Blue)
        .trace(Color::BrightBlack)
        .color(level)
}

fn color_enabled() -> bool {
    clicolors_control::colors_enabled() && atty::is(Stream::Stdout)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_verbosity() {
        assert_eq!(LevelFilter::Off, parse_verbosity(0));
        assert_eq!(LevelFilter::Warn, parse_verbosity(1));
        assert_eq!(LevelFilter::Info, parse_verbosity(2));
        assert_eq!(LevelFilter::Debug, parse_verbosity(3));
        assert_eq!(LevelFilter::Trace, parse_verbosity(4));
        assert_eq!(LevelFilter::Trace, parse_verbosity(100));
    }

    #[test]
    fn test_color_level_error() {
        let level = format!("{}", color_level(Level::Error));

        assert_eq!("\u{1b}[31mERROR\u{1b}[0m", &level);
    }

    #[test]
    fn test_color_level_warn() {
        let level = format!("{}", color_level(Level::Warn));

        assert_eq!("\u{1b}[33mWARN\u{1b}[0m", &level);
    }

    #[test]
    fn test_color_level_info() {
        let level = format!("{}", color_level(Level::Info));

        assert_eq!("\u{1b}[34mINFO\u{1b}[0m", &level);
    }

    #[test]
    fn test_color_level_debug() {
        let level = format!("{}", color_level(Level::Debug));

        assert_eq!("\u{1b}[37mDEBUG\u{1b}[0m", &level);
    }

    #[test]
    fn test_color_level_trace() {
        let level = format!("{}", color_level(Level::Trace));

        assert_eq!("\u{1b}[90mTRACE\u{1b}[0m", &level);
    }
}
