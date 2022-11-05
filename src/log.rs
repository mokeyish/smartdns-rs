
use std::{env, fmt};

use time::OffsetDateTime;
use tracing::{Subscriber, Event};
use tracing_subscriber::{fmt::{FormatEvent, FormatFields, FmtContext, FormattedFields, format}, registry::LookupSpan, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

pub use tracing::{
    debug, warn, error, info, trace
};


pub fn logger(level: tracing::Level) {
  // Setup tracing for logging based on input
  let filter = tracing_subscriber::EnvFilter::builder()
      .with_default_directive(tracing::Level::WARN.into())
      .parse(all_trust_dns(level))
      .expect("failed to configure tracing/logging");

  let formatter = tracing_subscriber::fmt::layer()
  .event_format(TdnsFormatter{
    level
  });

  tracing_subscriber::registry()
      .with(formatter)
      .with(filter)
      .init();
}

fn all_trust_dns(level: impl ToString) -> String {
  format!(
      "named={level},smartdns={level},{env}",
      level = level.to_string().to_lowercase(),
      env = get_env()
  )
}

fn get_env() -> String {
  env::var("RUST_LOG").unwrap_or_default()
}

struct TdnsFormatter{
    level: tracing::Level
}

impl<S, N> FormatEvent<S, N> for TdnsFormatter
where
  S: Subscriber + for<'a> LookupSpan<'a>,
  N: for<'a> FormatFields<'a> + 'static,
{
  fn format_event(
      &self,
      ctx: &FmtContext<'_, S, N>,
      mut writer: format::Writer<'_>,
      event: &Event<'_>,
  ) -> fmt::Result {
      let now = OffsetDateTime::now_utc();
      let now_secs = now.unix_timestamp();

      // Format values from the event's's metadata:
      let metadata = event.metadata();

      if self.level == tracing::Level::INFO {
        write!(
            &mut writer,
            "{}:{}",
            now_secs,
            metadata.level()
        )?;
      } else {
        
        write!(
            &mut writer,
            "{}:{}:{}",
            now_secs,
            metadata.level(),
            metadata.target()
        )?;
        if let Some(line) = metadata.line() {
            write!(&mut writer, ":{}", line)?;
        }
      }


      // Format all the spans in the event's span context.
      if let Some(scope) = ctx.event_scope() {
          for span in scope.from_root() {
              write!(writer, ":{}", span.name())?;

              let ext = span.extensions();
              let fields = &ext
                  .get::<FormattedFields<N>>()
                  .expect("will never be `None`");

              // Skip formatting the fields if the span had no fields.
              if !fields.is_empty() {
                  write!(writer, "{{{}}}", fields)?;
              }
          }
      }

      // Write fields on the event
      write!(writer, ": ")?;
      ctx.field_format().format_fields(writer.by_ref(), event)?;

      writeln!(writer)
  }
}
