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
