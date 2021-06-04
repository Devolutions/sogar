use clap::{crate_name, crate_version, App, Arg, ArgMatches};
use config::{Config as ConfigCache, ConfigError};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};

const REGISTRY_URL: &str = "registry-url";
const ENV_REGISTRY_URL: &str = "SOGAR_REGISTRY_URL";
const USERNAME: &str = "username";
const ENV_USERNAME: &str = "SOGAR_REGISTRY_USERNAME";
const PASSWORD: &str = "password";
const ENV_PASSWORD: &str = "SOGAR_REGISTRY_PASSWORD";
const MEDIA_TYPE: &str = "media-type";
const VALUE_MEDIA_TYPE: &str = "MEDIA_TYPE";
const REFERENCE: &str = "reference";
const VALUE_REFERENCE: &str = "REFERENCE";
const FILE_PATH: &str = "filepath";
const VALUE_FILE_PATH: &str = "FILE_PATH";
const EXPORT_ARTIFACT: &str = "export-artifact";
const VALUE_EXPORT_ARTIFACT: &str = "EXPORT_ARTIFACT";
const IMPORT_ARTIFACT: &str = "import-artifact";
const VALUE_IMPORT_ARTIFACT: &str = "IMPORT_ARTIFACT";
const ENV_REGISTRY_CACHE: &str = "SOGAR_REGISTRY_CACHE";
const REGISTRY_CACHE: &str = "registry-cache";
const COMMAND_DATA: &str = "command_data";
const COMMAND_TYPE: &str = "command_type";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum CommandType {
    Export,
    Import,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CommandData {
    #[serde(rename = "media-type")]
    pub media_type: String,
    pub reference: String,
    pub filepath: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Settings {
    #[serde(rename = "registry-url")]
    pub registry_url: String,
    pub username: String,
    pub password: String,
    pub command_type: CommandType,
    pub command_data: CommandData,
    #[serde(rename = "registry-cache")]
    pub registry_cache: Option<String>,
}

impl From<CommandType> for config::Value {
    fn from(val: CommandType) -> Self {
        match val {
            CommandType::Export => config::Value::from(String::from("Export")),
            CommandType::Import => config::Value::from(String::from("Import")),
        }
    }
}

pub fn match_arguments(matches: &ArgMatches, config_cache: &mut ConfigCache) -> Result<(), ConfigError> {
    if let Some(registry_url) = matches.value_of(REGISTRY_URL) {
        config_cache.set(REGISTRY_URL, registry_url.to_string())?;
    }

    if let Some(username) = matches.value_of(USERNAME) {
        config_cache.set(USERNAME, username.to_string())?;
    }

    if let Some(password) = matches.value_of(PASSWORD) {
        config_cache.set(PASSWORD, password.to_string())?;
    }

    if let Some(namespace) = matches.value_of(REFERENCE) {
        config_cache.set(
            format!("{}.{}", COMMAND_DATA, REFERENCE).as_str(),
            namespace.to_string(),
        )?;
    }

    let file_paths = matches
        .values_of(FILE_PATH)
        .unwrap_or_default()
        .map(|plugin| plugin.to_string())
        .collect::<Vec<String>>();

    for filepath in &file_paths {
        match matches.value_of(MEDIA_TYPE) {
            Some(media_type) => {
                config_cache.set(
                    format!("{}.{}", COMMAND_DATA, MEDIA_TYPE).as_str(),
                    media_type.to_string(),
                )?;
            }
            None => {
                config_cache.set(
                    format!("{}.{}", COMMAND_DATA, MEDIA_TYPE).as_str(),
                    get_mime_type_from_file_extension(filepath.to_string()),
                )?;
            }
        }
    }

    config_cache.set(format!("{}.{}", COMMAND_DATA, FILE_PATH).as_str(), file_paths)?;

    if let Some(sogar_cache) = matches.value_of(REGISTRY_CACHE) {
        config_cache.set(REGISTRY_CACHE, sogar_cache.to_string())?;
    }

    if matches.is_present(EXPORT_ARTIFACT) {
        config_cache.set(COMMAND_TYPE, CommandType::Export)?;
    }

    if matches.is_present(IMPORT_ARTIFACT) {
        config_cache.set(COMMAND_TYPE, CommandType::Import)?;
    }

    Ok(())
}

pub fn get_mime_type_from_file_extension(file_name: String) -> String {
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types

    let mut mime_mapping = HashMap::with_capacity(32);
    mime_mapping.insert(".zip", "application/zip");
    mime_mapping.insert(".bz", "application/x-bzip");
    mime_mapping.insert(".bz2", "application/x-bzip2");
    mime_mapping.insert(".tar", "application/x-tar");
    mime_mapping.insert(".7z", "application/x-7z-compressed");
    mime_mapping.insert(".pdf", "application/pdf");
    mime_mapping.insert(".json", "application/json");
    mime_mapping.insert(".js", "text/javascript");
    mime_mapping.insert(".htm", "text/html");
    mime_mapping.insert(".html", "text/html");
    mime_mapping.insert(".rtf", "application/rtf");
    mime_mapping.insert(".txt", "text/plain");
    mime_mapping.insert(".bmp", "image/bmp");
    mime_mapping.insert(".gif", "image/gif");
    mime_mapping.insert(".ico", "image/x-icon");
    mime_mapping.insert(".jpeg", "image/jpeg");
    mime_mapping.insert(".jpg", "image/jpeg");
    mime_mapping.insert(".png", "image/png");
    mime_mapping.insert(".svg", "image/svg+xml");
    mime_mapping.insert(".tif", "image/tiff");
    mime_mapping.insert(".tiff", "image/tiff");
    mime_mapping.insert(".webp", "image/webp");
    mime_mapping.insert(".mp4", "video/mp4");
    mime_mapping.insert(".mkv", "video/x-matroska");
    mime_mapping.insert(".mov", "video/quicktime");
    mime_mapping.insert(".avi", "video/x-msvideo");
    mime_mapping.insert(".wmv", "video/x-ms-wmv");
    mime_mapping.insert(".3gp", "video/3gpp");
    mime_mapping.insert(".flv", "video/x-flv");
    mime_mapping.insert(".webm", "video/webm");
    mime_mapping.insert(".mp3", "audio/mpeg");
    mime_mapping.insert(".wav", "audio/wav");
    mime_mapping.insert(".weba", "audio/webm");

    if let Some(extension) = Path::new(file_name.as_str()).extension() {
        if let Some(res) = mime_mapping.remove(format!(".{}", extension.to_str().unwrap()).as_str()) {
            return res.to_string();
        }
    };

    String::from("application/octet-stream")
}

pub fn create_command_line_app<'a, 'b>() -> App<'a, 'b> {
    App::new(crate_name!())
        .author("Devolutions Inc.")
        .version(concat!(crate_version!(), "\n"))
        .about("Sogar is a generic implementation of [OCI Artifacts](https://github.com/opencontainers/artifacts)")
        .arg(
            Arg::with_name(REGISTRY_URL)
                .long(REGISTRY_URL)
                .value_name(ENV_REGISTRY_URL)
                .help("Registry url to where the artifacts will be pushed.")
                .takes_value(true)
                .env(ENV_REGISTRY_URL)
                .required(true)
                .empty_values(false),
        )
        .arg(
            Arg::with_name(USERNAME)
                .short("u")
                .long(USERNAME)
                .value_name(ENV_USERNAME)
                .help("Registry username.")
                .takes_value(true)
                .env(ENV_USERNAME)
                .required(true)
                .empty_values(false),
        )
        .arg(
            Arg::with_name(PASSWORD)
                .short("p")
                .long(PASSWORD)
                .value_name(ENV_PASSWORD)
                .help("Registry password.")
                .takes_value(true)
                .env(ENV_PASSWORD)
                .required(true)
                .empty_values(false),
        )
        .arg(
            Arg::with_name(EXPORT_ARTIFACT)
                .long(EXPORT_ARTIFACT)
                .value_name(VALUE_EXPORT_ARTIFACT)
                .help("Command to export the file to the registry.")
                .takes_value(false)
                .requires_all(&[REFERENCE, FILE_PATH]),
        )
        .arg(
            Arg::with_name(MEDIA_TYPE)
                .long(MEDIA_TYPE)
                .value_name(VALUE_MEDIA_TYPE)
                .help("Media type of the file. If not set the default one will be used.")
                .takes_value(true)
                .empty_values(false),
        )
        .arg(
            Arg::with_name(REFERENCE)
                .long(REFERENCE)
                .value_name(VALUE_REFERENCE)
                .help("Namespace of the registry where to push the file.")
                .takes_value(true)
                .empty_values(false),
        )
        .arg(
            Arg::with_name(FILE_PATH)
                .long(FILE_PATH)
                .value_name(VALUE_FILE_PATH)
                .help("Path of the file that will be exported.")
                .takes_value(true)
                .empty_values(false)
                .multiple(true)
                .use_delimiter(true)
                .value_delimiter(";")
                .number_of_values(1),
        )
        .arg(
            Arg::with_name(IMPORT_ARTIFACT)
                .long(IMPORT_ARTIFACT)
                .value_name(VALUE_IMPORT_ARTIFACT)
                .help("Command to import the file to the registry.")
                .takes_value(false)
                .requires_all(&[REFERENCE, FILE_PATH]),
        )
        .arg(
            Arg::with_name(REGISTRY_CACHE)
                .long(REGISTRY_CACHE)
                .value_name(ENV_REGISTRY_CACHE)
                .help("Path to the directory where cache will be located.")
                .takes_value(true)
                .env(ENV_REGISTRY_CACHE)
                .empty_values(false),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_contains_value() {
        let res = get_mime_type_from_file_extension(String::from("test.json"));

        assert_eq!(String::from("application/json"), res);
    }

    #[test]
    fn test_map_not_contains_value() {
        let res = get_mime_type_from_file_extension(String::from("test.pcap"));

        assert_eq!(String::from("application/octet-stream"), res);
    }
}
