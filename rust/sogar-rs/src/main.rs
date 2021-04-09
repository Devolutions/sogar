use crate::{
    logger::init_logger,
    sogar::{
        export_sogar_file_artifact,
        sogar_config::{create_command_line_app, match_arguments, Settings},
    },
};
use config::Config as ConfigCache;
use slog_scope_futures::FutureExt;

mod logger;
mod sogar;

#[tokio::main]
async fn main() -> Result<(), String> {
    let logger = init_logger(None);

    let app = create_command_line_app();
    let matches = app.get_matches();
    let mut cache = ConfigCache::new();
    match_arguments(&matches, &mut cache).unwrap();

    let settings: Settings = cache.try_into().unwrap();
    slog_scope::info!("setting are: {:?}", settings);

    export_sogar_file_artifact(&settings)
        .with_logger(logger.clone())
        .await
        .unwrap();

    Ok(())
}
