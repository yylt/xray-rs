use xray_rs::root;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn level_letter(level: log::Level) -> char {
    match level {
        log::Level::Error => 'E',
        log::Level::Warn => 'W',
        log::Level::Info => 'I',
        log::Level::Debug => 'D',
        log::Level::Trace => 'T',
    }
}

fn compact_date_mmdd() -> String {
    use time::OffsetDateTime;

    match OffsetDateTime::now_local() {
        Ok(now) => format!("{:02}{:02}", u8::from(now.month()), now.day()),
        Err(_) => {
            let now = OffsetDateTime::now_utc();
            format!("{:02}{:02}", u8::from(now.month()), now.day())
        }
    }
}

fn format_log_prefix(level: log::Level, target: &str, message: &str) -> String {
    let target = if target.is_empty() { "unknown" } else { target };
    let prefix = format!("{}{} {}", level_letter(level), compact_date_mmdd(), target);

    if message.is_empty() {
        prefix
    } else {
        format!("{prefix}] {message}")
    }
}

fn main() {
    // Initialize logging
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .format(|buf, record| {
            use std::io::Write;

            let message = format!("{}", record.args());
            writeln!(buf, "{}", format_log_prefix(record.level(), record.target(), &message))
        })
        .init();

    match root::execute() {
        Err(e) => {
            println!("execute error: {e}");
        }
        _ => {}
    }
}
