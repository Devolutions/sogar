use clap::{crate_name, crate_version, App, Arg, ArgMatches};
use config::{Config as ConfigCache, ConfigError};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};

static REGISTRY_URL: &str = "registry-url";
static ENV_REGISTRY_URL: &str = "REGISTRY_URL";
static USERNAME: &str = "username";
static ENV_USERNAME: &str = "USERNAME";
static PASSWORD: &str = "password";
static ENV_PASSWORD: &str = "PASSWORD";
static MEDIA_TYPE: &str = "media-type";
static VALUE_MEDIA_TYPE: &str = "MEDIA_TYPE";
static REFERENCE: &str = "reference";
static VALUE_REFERENCE: &str = "REFERENCE";
static FILE_PATH: &str = "filepath";
static VALUE_FILE_PATH: &str = "FILE_PATH";
static EXPORT_ARTIFACT: &str = "export-artifact";
static VALUE_EXPORT_ARTIFACT: &str = "EXPORT_ARTIFACT";
static EXPORT: &str = "export";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Export {
    #[serde(rename = "media-type")]
    pub media_type: String,
    pub reference: String,
    pub filepath: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Settings {
    #[serde(rename = "registry-url")]
    pub registry_url: String,
    pub username: String,
    pub password: String,
    pub export: Option<Export>,
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

    if matches.is_present(EXPORT_ARTIFACT) {
        if let Some(namespace) = matches.value_of(REFERENCE) {
            config_cache.set(format!("{}.{}", EXPORT, REFERENCE).as_str(), namespace.to_string())?;
        }

        if let Some(filepath) = matches.value_of(FILE_PATH) {
            config_cache.set(format!("{}.{}", EXPORT, FILE_PATH).as_str(), filepath.to_string())?;

            if let Some(media_type) = matches.value_of(MEDIA_TYPE) {
                config_cache.set(format!("{}.{}", EXPORT, MEDIA_TYPE).as_str(), media_type.to_string())?;
            } else {
                config_cache.set(
                    format!("{}.{}", EXPORT, MEDIA_TYPE).as_str(),
                    get_mime_type_from_file_extension(filepath.to_string()),
                )?;
            }
        }
    }

    Ok(())
}

fn get_mime_type_from_file_extension(file_name: String) -> String {
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
