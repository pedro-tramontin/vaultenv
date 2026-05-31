//! Shared types used across vaultenv modules.

/// Log level for vaultenv output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum LogLevel {
    /// Most verbose; every tracing span is emitted.
    Trace,
    /// Detailed debugging information.
    Debug,
    /// Informational messages about progress.
    Info,
    /// Potentially problematic conditions.
    Warn,
    /// Print errors only (default).
    #[default]
    Error,
}

/// Behavior when duplicate environment variables are detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DuplicateBehavior {
    /// Produce an error (default).
    #[default]
    Error,
    /// Keep the existing variable, ignore the secret.
    Keep,
    /// Overwrite the existing variable with the secret value.
    Overwrite,
}

// ---------------------------------------------------------------------------
// clap value parsers
// ---------------------------------------------------------------------------

/// Thin clap wrapper around [`LogLevel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogLevelArg(pub LogLevel);

impl Default for LogLevelArg {
    fn default() -> Self {
        LogLevelArg(LogLevel::Error)
    }
}

impl std::str::FromStr for LogLevelArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "trace" => Ok(LogLevelArg(LogLevel::Trace)),
            "debug" => Ok(LogLevelArg(LogLevel::Debug)),
            "info" => Ok(LogLevelArg(LogLevel::Info)),
            "warn" => Ok(LogLevelArg(LogLevel::Warn)),
            "error" => Ok(LogLevelArg(LogLevel::Error)),
            _ => Err(format!(
                "unknown log level '{}', expected trace|debug|info|warn|error",
                s
            )),
        }
    }
}

impl std::fmt::Display for LogLevelArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self.0 {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        };
        write!(f, "{s}")
    }
}

/// Thin clap wrapper around [`DuplicateBehavior`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateBehaviorArg(pub DuplicateBehavior);

impl Default for DuplicateBehaviorArg {
    fn default() -> Self {
        DuplicateBehaviorArg(DuplicateBehavior::Error)
    }
}

impl std::str::FromStr for DuplicateBehaviorArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "error" => Ok(DuplicateBehaviorArg(DuplicateBehavior::Error)),
            "keep" => Ok(DuplicateBehaviorArg(DuplicateBehavior::Keep)),
            "overwrite" => Ok(DuplicateBehaviorArg(DuplicateBehavior::Overwrite)),
            _ => Err(format!(
                "unknown duplicate behavior '{}', expected error|keep|overwrite",
                s
            )),
        }
    }
}

impl std::fmt::Display for DuplicateBehaviorArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self.0 {
            DuplicateBehavior::Error => "error",
            DuplicateBehavior::Keep => "keep",
            DuplicateBehavior::Overwrite => "overwrite",
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_from_str() {
        assert!(matches!(
            "trace".parse::<LogLevelArg>().unwrap().0,
            LogLevel::Trace
        ));
        assert!(matches!(
            "debug".parse::<LogLevelArg>().unwrap().0,
            LogLevel::Debug
        ));
        assert!(matches!(
            "info".parse::<LogLevelArg>().unwrap().0,
            LogLevel::Info
        ));
        assert!(matches!(
            "warn".parse::<LogLevelArg>().unwrap().0,
            LogLevel::Warn
        ));
        assert!(matches!(
            "error".parse::<LogLevelArg>().unwrap().0,
            LogLevel::Error
        ));
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(LogLevelArg(LogLevel::Trace).to_string(), "trace");
        assert_eq!(LogLevelArg(LogLevel::Debug).to_string(), "debug");
        assert_eq!(LogLevelArg(LogLevel::Info).to_string(), "info");
        assert_eq!(LogLevelArg(LogLevel::Warn).to_string(), "warn");
        assert_eq!(LogLevelArg(LogLevel::Error).to_string(), "error");
    }

    #[test]
    fn test_duplicate_behavior_from_str() {
        assert!(matches!(
            "error".parse::<DuplicateBehaviorArg>().unwrap().0,
            DuplicateBehavior::Error
        ));
        assert!(matches!(
            "keep".parse::<DuplicateBehaviorArg>().unwrap().0,
            DuplicateBehavior::Keep
        ));
        assert!(matches!(
            "overwrite".parse::<DuplicateBehaviorArg>().unwrap().0,
            DuplicateBehavior::Overwrite
        ));
    }
}
