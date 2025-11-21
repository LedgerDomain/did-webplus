#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum LogFormat {
    Compact,
    JSON,
    Pretty,
}

pub fn init_logging(log_format: LogFormat) {
    // It's necessary to specify EnvFilter::from_default_env in order to use RUST_LOG env var.
    let tracing_subscriber_fmt = tracing_subscriber::fmt()
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_span_events(
            tracing_subscriber::fmt::format::FmtSpan::NEW
                | tracing_subscriber::fmt::format::FmtSpan::CLOSE,
        )
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env());

    match log_format {
        LogFormat::Compact => tracing_subscriber_fmt.compact().init(),
        LogFormat::JSON => tracing_subscriber_fmt.json().init(),
        LogFormat::Pretty => tracing_subscriber_fmt.pretty().init(),
    }
}
