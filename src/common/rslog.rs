use serde::{Deserialize, Serialize};
use slog::Drain;
use std::{
    fs::OpenOptions,
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use time::OffsetDateTime;

/// 日志配置，由配置文件顶层 `log` 字段反序列化而来。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LogSettings {
    /// 日志文件路径；缺省时输出到 stderr。
    #[serde(rename = "file", default)]
    pub file: Option<PathBuf>,
    /// 过滤级别，默认 info。
    #[serde(rename = "level", default)]
    pub level: LogLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    /// 转为 slog 过滤阈值。slog 阈值越低表示输出越多（Critical 最严，Trace 最松），
    /// `Off` 无对应枚举，用最严的 Critical 表示全部丢弃。
    fn to_slog_level(self) -> slog::Level {
        match self {
            LogLevel::Off => slog::Level::Critical,
            LogLevel::Error => slog::Level::Error,
            LogLevel::Warn => slog::Level::Warning,
            LogLevel::Info => slog::Level::Info,
            LogLevel::Debug => slog::Level::Debug,
            LogLevel::Trace => slog::Level::Trace,
        }
    }

    /// 转为 slog-stdlog 的 log 过滤级别。与旧实现保持一致：`Off` 映射为 Error。
    fn to_log_level(self) -> log::Level {
        match self {
            LogLevel::Off | LogLevel::Error => log::Level::Error,
            LogLevel::Warn => log::Level::Warn,
            LogLevel::Info => log::Level::Info,
            LogLevel::Debug => log::Level::Debug,
            LogLevel::Trace => log::Level::Trace,
        }
    }
}

pub struct AsyncGuard {
    _scope_guard: slog_scope::GlobalLoggerGuard,
    _async_guard: slog_async::AsyncGuard,
}

/// 初始化日志：输出到 `settings.file`（配置了）或 stderr（默认），
/// 过滤级别取 `settings.level`（默认 info）。
pub fn init(settings: &LogSettings) -> io::Result<AsyncGuard> {
    let slog_level = settings.level.to_slog_level();

    let writer: Arc<dyn WriteLog> = match &settings.file {
        Some(path) => Arc::new(FileWriter::new(path)?),
        None => Arc::new(StderrWriter),
    };
    let drain = FormatDrain {
        writer,
        max_level: slog_level,
    };

    let (drain, async_guard) = slog_async::Async::new(drain)
        .chan_size(16384)
        .thread_name("slog-io".into())
        .build_with_guard();

    let logger = slog::Logger::root(drain.fuse(), slog::o!());
    let scope_guard = slog_scope::set_global_logger(logger);
    slog_stdlog::init_with_level(settings.level.to_log_level()).map_err(|e| io::Error::other(e.to_string()))?;

    Ok(AsyncGuard {
        _scope_guard: scope_guard,
        _async_guard: async_guard,
    })
}

/// 日志写入后端：stderr 与文件共用同一种输出格式。
trait WriteLog: Send + Sync {
    fn write(&self, line: &str);
}

struct StderrWriter;

impl WriteLog for StderrWriter {
    fn write(&self, line: &str) {
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "{}", line);
    }
}

/// 追加写日志文件。所有记录在 slog-io 单线程上格式化，文件写经互斥保护。
struct FileWriter {
    file: Mutex<std::fs::File>,
}

impl FileWriter {
    fn new(path: &PathBuf) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file: Mutex::new(file) })
    }
}

impl WriteLog for FileWriter {
    fn write(&self, line: &str) {
        use std::io::Write;
        let file = &self.file;
        if let Ok(mut file) = file.lock() {
            let _ = writeln!(file, "{}", line);
        }
    }
}

struct FormatDrain {
    writer: Arc<dyn WriteLog>,
    max_level: slog::Level,
}

impl Drain for FormatDrain {
    type Ok = ();
    type Err = slog::Never;

    fn log(&self, record: &slog::Record<'_>, _values: &slog::OwnedKVList) -> Result<Self::Ok, Self::Err> {
        if !record.level().is_at_least(self.max_level) {
            return Ok(());
        }

        let level_char = match record.level() {
            slog::Level::Critical | slog::Level::Error => 'E',
            slog::Level::Warning => 'W',
            slog::Level::Info => 'I',
            slog::Level::Debug => 'D',
            slog::Level::Trace => 'T',
        };

        let date = match OffsetDateTime::now_local() {
            Ok(now) => format!("{:02}{:02}", u8::from(now.month()), now.day()),
            Err(_) => {
                let now = OffsetDateTime::now_utc();
                format!("{:02}{:02}", u8::from(now.month()), now.day())
            }
        };

        let target = record.module();
        let function = record.function();
        let source = if !function.is_empty() {
            format!("{}::{}", target, function)
        } else {
            target.to_string()
        };

        self.writer
            .write(&format!("{level_char}{date} [{source}] {}", record.msg()));
        Ok(())
    }
}
