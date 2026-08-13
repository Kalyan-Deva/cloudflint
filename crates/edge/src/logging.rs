//! Log setup, shared by both binaries.
//!
//! Human-readable stays the default, because the person most likely to read a log
//! locally is whoever just started the process. Set `CLOUDVEIL_LOG_FORMAT=json` and
//! every line becomes one JSON object instead, which is what a log shipper wants -
//! same events, same fields, no parsing of a format that was never meant to be parsed.

use tracing_subscriber::EnvFilter;

pub const FORMAT_VAR: &str = "CLOUDVEIL_LOG_FORMAT";

/// Install the subscriber. Call once, first thing in `main`.
pub fn init() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var(FORMAT_VAR)
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if json {
        tracing_subscriber::fmt()
            .json()
            /* the message and any fields land at the top level rather than nested
               under "fields", which is what most queries expect to find them at */
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false)
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .init();
    }
}
