use std::{env, fmt, io, path::Path, sync::OnceLock};

use tracing::{
    Dispatch, Event, Subscriber,
    dispatcher::{set_default, set_global_default},
    subscriber::DefaultGuard,
};
use tracing_subscriber::{
    EnvFilter,
    fmt::{
        FmtContext, FormatEvent, FormatFields, FormattedFields, MakeWriter, format,
        writer::MakeWriterExt,
    },
    prelude::__tracing_subscriber_SubscriberExt,
    registry::LookupSpan,
};

static CONSOLE_LEVEL: OnceLock<Level> = OnceLock::new();

pub use tracing::*;

type MappedFile = crate::infra::mapped_file::MutexMappedFile;

pub fn init_global_default<P: AsRef<Path>>(
    path: P,
    level: Level,
    filter: Option<&str>,
    size: u64,
    num: u64,
    mode: Option<u32>,
    to_console: bool,
) -> DefaultGuard {
    let file = MappedFile::open(path.as_ref(), size, Some(num as usize), mode);

    let writable = file
        .0
        .lock()
        .unwrap()
        .touch()
        .map(|_| true)
        .unwrap_or_else(|err| {
            warn!("{:?}, {:?}", path.as_ref(), err);
            false
        });

    let console_level = if to_console {
        level
    } else {
        *CONSOLE_LEVEL.get_or_init(|| Level::INFO)
    };
    let console_writer = io::stdout.with_max_level(console_level);

    let dispatch = if writable {
        // log hello
        {
            let writer = file.with_max_level(level);
            let dispatch = make_dispatch(level, filter, writer);

            let _guard = set_default(&dispatch);
            crate::hello_starting();
        }

        let file_writer =
            MappedFile::open(path.as_ref(), size, Some(num as usize), mode).with_max_level(level);

        make_dispatch(
            level.max(console_level),
            filter,
            file_writer.and(console_writer),
        )
    } else {
        make_dispatch(console_level, filter, console_writer)
    };

    let guard = set_default(&dispatch);

    set_global_default(dispatch).expect("");
    guard
}

pub fn default(console_level: Level) -> DefaultGuard {
    CONSOLE_LEVEL.get_or_init(|| console_level);
    let console_writer = io::stdout.with_max_level(console_level);
    set_default(&make_dispatch(console_level, None, console_writer))
}

#[inline]
fn make_dispatch<W: for<'writer> MakeWriter<'writer> + 'static + Send + Sync>(
    level: tracing::Level,
    filter: Option<&str>,
    writer: W,
) -> Dispatch {
    let layer = tracing_subscriber::fmt::layer()
        .event_format(TdnsFormatter)
        .with_writer(writer);

    Dispatch::from(
        tracing_subscriber::registry()
            .with(layer)
            .with(make_filter(level, filter)),
    )
}

#[inline]
fn make_filter(level: tracing::Level, filter: Option<&str>) -> EnvFilter {
    EnvFilter::builder()
        .with_default_directive(tracing::Level::WARN.into())
        .parse(all_smart_dns(level, filter))
        .expect("failed to configure tracing/logging")
}

#[inline]
fn all_smart_dns(level: impl ToString, filter: Option<&str>) -> String {
    filter
        .unwrap_or("named={level},smartdns={level},{env}")
        .replace("{level}", level.to_string().to_uppercase().as_str())
        .replace("{env}", get_env().as_str())
}

#[inline]
fn get_env() -> String {
    env::var("RUST_LOG").unwrap_or_default()
}

struct TdnsFormatter;

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
        let now = chrono::Local::now();
        let now_msecs = now.timestamp_millis() % 1000;
        let date = now.format("%Y-%m-%d %H:%M:%S");

        // Format values from the event's's metadata:
        let metadata = event.metadata();

        if metadata.level() == &tracing::Level::INFO {
            write!(&mut writer, "{}.{}:{}", date, now_msecs, metadata.level())?;
        } else {
            write!(
                &mut writer,
                "{}.{}:{}:{}",
                date,
                now_msecs,
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

impl<'a> MakeWriter<'a> for MappedFile {
    type Writer = &'a MappedFile;
    fn make_writer(&'a self) -> Self::Writer {
        self
    }
}
