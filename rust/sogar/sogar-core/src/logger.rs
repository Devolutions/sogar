use slog::Drain;
use slog::FnValue;
use slog::{o, FilterLevel, Fuse, Logger};
use slog_async::{Async, OverflowStrategy};
use slog_envlogger::LogBuilder;
use slog_scope::set_global_logger;
use slog_term::FullFormat;
use slog_term::TermDecorator;
use slog_term::{Decorator, PlainDecorator};
use std::env;
use std::fs::OpenOptions;

const DEFAULT_CHAIN_SIZE: usize = 256;
const RUST_LOG: &str = "RUST_LOG";

pub fn init_logger(file_path: Option<String>) -> Logger {
    let logger = setup_logger(file_path);
    let global_logger = set_global_logger(logger.clone());
    slog_stdlog::init().expect("failed to init logger");
    global_logger.cancel_reset();
    logger
}

fn setup_logger(file_path: Option<String>) -> Logger {
    let drain = match file_path {
        Some(file_path) => {
            let outfile = OpenOptions::new().create(true).append(true).open(file_path).unwrap();

            let file_decorator = PlainDecorator::new(outfile);
            create_drain(file_decorator)
        }
        None => {
            let decorator = TermDecorator::new().build();
            create_drain(decorator)
        }
    };

    Logger::root(
        drain,
        o!("module" => FnValue(move |info| {
            format!("[{}]", info.module())
        })),
    )
}

fn create_drain<T: Decorator + Send + 'static>(decorator: T) -> Fuse<Async> {
    let drain_decorator = FullFormat::new(decorator).build().fuse();
    let env_drain = LogBuilder::new(drain_decorator)
        .filter(None, FilterLevel::Info)
        .parse(env::var(RUST_LOG).unwrap_or_default().as_str())
        .build();

    Async::new(env_drain.fuse())
        .chan_size(DEFAULT_CHAIN_SIZE)
        .overflow_strategy(OverflowStrategy::DropAndReport)
        .build()
        .fuse()
}
