// Std imports
use std::sync::{Mutex, MutexGuard};

// External imports
use lazy_static::lazy_static;

// Internal imports
use crate::types::Format;

lazy_static! {
    pub static ref FORMAT_MODE: FormatMode = FormatMode::new();
}

#[derive(Debug)]
pub struct FormatMode(Mutex<FormatModeInner>);

impl FormatMode {
    fn new() -> Self {
        Self(Mutex::new(FormatModeInner::new()))
    }

    pub fn init(&self, format: Format, salt_format: Format) {
        self.lock().init(format, salt_format)
    }

    fn set(&self, format: Format, salt_format: Format) {
        self.lock().set(format, salt_format);
    }

    pub fn format(&self) -> Format {
        self.lock().format()
    }

    pub fn salt_format(&self) -> Format {
        self.lock().salt_format()
    }

    fn lock(&self) -> MutexGuard<FormatModeInner> {
        self.0.lock().unwrap_or_else(|err| err.into_inner())
    }

    pub fn test_with_formats<F: FnOnce() -> ()>(
        &self,
        format: Format,
        salt_format: Format,
        test: F,
    ) {
        self.set(format, salt_format);
        test();
    }

    pub fn test_with_salt_format<F: FnOnce() -> ()>(&self, salt_format: Format, test: F) {
        self.test_with_formats(Format::Hex, salt_format, test);
    }
}

#[derive(Debug)]
struct FormatModeInner {
    format: Option<Format>,
    salt_format: Option<Format>,
}

impl FormatModeInner {
    fn new() -> Self {
        Self {
            format: None,
            salt_format: None,
        }
    }

    fn is_initialised(&self) -> bool {
        self.format.is_some() && self.salt_format.is_some()
    }

    fn init(&mut self, format: Format, salt_format: Format) {
        debug_assert!(!self.is_initialised(), "FORMAT_MODE already initialised");

        self.set(format, salt_format);
    }

    fn set(&mut self, format: Format, salt_format: Format) {
        self.format = Some(format);
        self.salt_format = Some(salt_format);
    }

    fn format(&self) -> Format {
        debug_assert!(self.is_initialised(), "FORMAT_MODE not yet initialised");

        self.format.unwrap()
    }

    fn salt_format(&self) -> Format {
        debug_assert!(self.is_initialised(), "FORMAT_MODE not yet initialised");

        self.salt_format.unwrap()
    }
}

pub fn get_format() -> Format {
    FORMAT_MODE.format()
}

pub fn get_salt_format() -> Format {
    FORMAT_MODE.salt_format()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_format_mode_inner_new() {
        let inner = FormatModeInner::new();
        assert_eq!(None, inner.format);
        assert_eq!(None, inner.salt_format);
    }

    #[test]
    fn test_format_mode_inner_is_initialised() {
        let mut inner = FormatModeInner::new();
        assert!(!inner.is_initialised());
        inner.init(Format::Hex, Format::Hex);
        assert!(inner.is_initialised());
    }

    #[test]
    fn test_format_mode_inner_init() {
        let mut inner = FormatModeInner::new();
        inner.init(Format::Bytes, Format::Base64);
        assert_eq!(Format::Bytes, inner.format.unwrap());
        assert_eq!(Format::Base64, inner.salt_format.unwrap());
    }

    #[test]
    #[should_panic(expected = "FORMAT_MODE already initialised")]
    fn test_format_mode_inner_init_twice_should_panic() {
        let mut inner = FormatModeInner::new();
        inner.init(Format::Hex, Format::Hex);
        inner.init(Format::Base64, Format::Base64);
    }

    #[test]
    fn test_format_mode_inner_set() {
        let mut inner = FormatModeInner::new();
        inner.init(Format::Hex, Format::Hex);
        inner.set(Format::Base64, Format::Bytes);
        assert_eq!(Format::Base64, inner.format.unwrap());
        assert_eq!(Format::Bytes, inner.salt_format.unwrap());
    }

    #[test]
    #[should_panic(expected = "FORMAT_MODE not yet initialised")]
    fn test_format_mode_inner_get_format_uninitialised_should_panic() {
        let inner = FormatModeInner::new();
        inner.format();
    }

    #[test]
    #[should_panic(expected = "FORMAT_MODE not yet initialised")]
    fn test_format_mode_inner_get_salt_format_uninitialised_should_panic() {
        let inner = FormatModeInner::new();
        inner.salt_format();
    }

    #[test]
    fn test_format_mode_inner_get_format() {
        let mut inner = FormatModeInner::new();
        inner.init(Format::Bytes, Format::Hex);
        assert_eq!(Format::Bytes, inner.format());
    }

    #[test]
    fn test_format_mode_inner_get_salt_format() {
        let mut inner = FormatModeInner::new();
        inner.init(Format::Hex, Format::Base64);
        assert_eq!(Format::Base64, inner.salt_format());
    }

    #[test]
    fn test_format_mode_init() {
        let mode = FormatMode::new();
        mode.init(Format::Base64, Format::Bytes);
        assert_eq!(Format::Base64, mode.format());
        assert_eq!(Format::Bytes, mode.salt_format());
    }

    #[test]
    #[should_panic(expected = "FORMAT_MODE already initialised")]
    fn test_format_mode_init_twice_should_panic() {
        let mode = FormatMode::new();
        mode.init(Format::Hex, Format::Hex);
        mode.init(Format::Base64, Format::Base64);
    }

    #[test]
    fn test_format_mode_set() {
        let mode = FormatMode::new();
        mode.init(Format::Hex, Format::Hex);
        mode.set(Format::Base64, Format::Bytes);
        assert_eq!(Format::Base64, mode.format());
        assert_eq!(Format::Bytes, mode.salt_format());
    }

    #[test]
    #[should_panic(expected = "FORMAT_MODE not yet initialised")]
    fn test_format_mode_get_format_uninitialised_should_panic() {
        let mode = FormatMode::new();
        mode.format();
    }

    #[test]
    #[should_panic(expected = "FORMAT_MODE not yet initialised")]
    fn test_format_mode_get_salt_format_uninitialised_should_panic() {
        let mode = FormatMode::new();
        mode.salt_format();
    }

    #[test]
    fn test_format_mode_get_format() {
        let mode = FormatMode::new();
        mode.init(Format::Bytes, Format::Hex);
        assert_eq!(Format::Bytes, mode.format());
    }

    #[test]
    fn test_format_mode_get_salt_format() {
        let mode = FormatMode::new();
        mode.init(Format::Hex, Format::Base64);
        assert_eq!(Format::Base64, mode.salt_format());
    }

    #[test]
    fn test_format_mode_lock() {
        let mode = FormatMode::new();
        let _ = mode.lock();
    }

    #[test]
    fn test_get_format() {
        FORMAT_MODE.test_with_formats(Format::Base64, Format::Bytes, || {
            let format = get_format();
            assert_eq!(Format::Base64, format);
        });
    }

    #[test]
    fn test_get_salt_format() {
        FORMAT_MODE.test_with_formats(Format::Base64, Format::Bytes, || {
            let format = get_salt_format();
            assert_eq!(Format::Bytes, format);
        });
    }
}
